#include "monitor.h"

#include <Windows.h>
#include <ShlObj.h>
#include <Psapi.h>
#include <DbgHelp.h>
#include <evntrace.h>
#include <evntcons.h>

#include <atomic>
#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#pragma comment(lib, "Advapi32.lib")

namespace SkyOS {
    namespace {
        // Kernel sampled-profile events contain the instruction pointer and
        // thread ID. We aggregate instruction pointers by their mapped image;
        // this is sampling attribution, not a claim of exact per-DLL CPU time.
        constexpr UCHAR kSampledProfileOpcode = 46;
        // SampledProfile events are emitted under the PerfInfo task GUID. The
        // session itself is still the NT Kernel Logger (SystemTraceControlGuid).
        constexpr GUID kSystemTraceControlGuid{ 0x9e814aad, 0x3204, 0x11d2, { 0x9a, 0x82, 0x00, 0x60, 0x08, 0xa8, 0x69, 0x39 } };
        constexpr GUID kPerfInfoGuid{ 0xce1dbfb4, 0x137e, 0x4da6, { 0x87, 0xb0, 0x3f, 0x59, 0xaa, 0x10, 0x2c, 0xbc } };
        // Kernel stack traces are delivered as separate StackWalk events, not
        // necessarily as STACK_TRACE extended data on the sampled-profile event.
        constexpr GUID kStackWalkGuid{ 0xdef2fe46, 0x7bd6, 0x4b80, { 0xbd, 0x94, 0xf5, 0x7f, 0xe2, 0x0d, 0x0c, 0xe3 } };
        constexpr UCHAR kStackWalkOpcode = 32;
        struct ModuleSamples { std::uint64_t count{}; };
        struct FunctionSamples { std::string module; std::string name; std::string category; bool symbolResolved{}; std::uint64_t count{}; };
        std::mutex g_profileMutex;
        std::unordered_map<std::string, ModuleSamples> g_moduleSamples;
        std::unordered_map<std::uintptr_t, std::string> g_moduleNames;
        std::unordered_map<std::uintptr_t, std::uint64_t> g_stackAddressSamples;
        std::vector<FunctionSamples> g_functionSamples;
        std::uint64_t g_stackFrameCount{};
        std::atomic_bool g_stackCaptureEnabled{ false };
        ULONG g_stackTraceError{};
        std::atomic<std::uint64_t> g_stackWalkEventsSeen{ 0 };
        std::atomic<std::uint64_t> g_stackWalkMatched{ 0 };
        std::string g_stackCaptureStatus{"Call-stack capture has not been attempted"};
        std::string g_stackResolutionStatus{"No call-stack capture yet"};
        std::thread g_profileThread;
        std::atomic_bool g_profileStop{ false };
        std::atomic_bool g_profileActive{ false };
        std::atomic<std::uint64_t> g_eventsSeen{ 0 };
        std::atomic<std::uint64_t> g_profileEventsSeen{ 0 };
        std::atomic<std::uint64_t> g_threadMatched{ 0 };
        std::string g_profileStatus{ "Deep profiling is off" };
        TRACEHANDLE g_profileSession{};
        TRACEHANDLE g_profileConsumer{ INVALID_PROCESSTRACE_HANDLE };
        SYSTEMTIME g_profileStartedAt{};
        SYSTEMTIME g_profileStoppedAt{};
        std::uint64_t g_frameTimeSamples{};
        double g_frameTimeTotalMs{};
        double g_frameTimeMinMs{};
        double g_frameTimeMaxMs{};
        std::unordered_map<std::string, std::uint64_t> g_previousModuleSamples;
        std::uint64_t g_previousSampleCount{};
        double g_previousFrameTimeMs{-1.0};
        std::string g_previousStarted;

        std::string Utf8(const wchar_t* text);

        std::string HexOffset(std::uintptr_t offset)
        {
            char text[32]{};
            std::snprintf(text, sizeof(text), "0x%llX", static_cast<unsigned long long>(offset));
            return text;
        }

        std::string FunctionCategory(std::string moduleName)
        {
            std::transform(moduleName.begin(), moduleName.end(), moduleName.begin(), [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
            if (moduleName == "skyrimse.exe" || moduleName == "skyrim.exe") return "Skyrim";
            if (moduleName.starts_with("nv") || moduleName.starts_with("nvidia") || moduleName.starts_with("amd") ||
                moduleName.starts_with("ati") || moduleName.starts_with("ig") || moduleName.starts_with("intel")) return "Graphics drivers";
            if (moduleName.starts_with("d3d") || moduleName.starts_with("dxgi") || moduleName.starts_with("dxcore") ||
                moduleName.starts_with("dwrite") || moduleName.starts_with("d2d") || moduleName.starts_with("xaudio") ||
                moduleName.starts_with("xinput") || moduleName.starts_with("vulkan") || moduleName.starts_with("opengl")) return "Graphics and audio runtime";
            constexpr std::string_view systemPrefixes[]{ "ntdll", "kernel32", "kernelbase", "user32", "win32u", "gdi32", "advapi32", "sechost",
                "ucrtbase", "vcruntime", "msvcp", "combase", "ole32", "oleaut32", "rpcrt4", "ws2_32", "bcrypt", "crypt32", "shell32", "shcore", "ntoskrnl", "wow64" };
            if (std::any_of(std::begin(systemPrefixes), std::end(systemPrefixes), [&](auto prefix) { return moduleName.starts_with(prefix); })) return "Windows runtime";
            return "SKSE / third-party modules";
        }

        void ResolveStackFrames()
        {
            if (g_stackAddressSamples.empty()) {
                std::scoped_lock lock(g_profileMutex);
                g_stackResolutionStatus = g_stackCaptureEnabled ? "No call-stack addresses were captured" : g_stackCaptureStatus;
                return;
            }
            HANDLE symbolProcess{};
            if (!DuplicateHandle(GetCurrentProcess(), GetCurrentProcess(), GetCurrentProcess(), &symbolProcess, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
                std::scoped_lock lock(g_profileMutex);
                g_stackResolutionStatus = "Could not create an isolated symbol session (Windows error " + std::to_string(GetLastError()) + ")";
                return;
            }
            const auto previousOptions = SymGetOptions();
            SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
            if (!SymInitialize(symbolProcess, nullptr, FALSE)) {
                const auto error = GetLastError();
                SymSetOptions(previousOptions);
                CloseHandle(symbolProcess);
                std::scoped_lock lock(g_profileMutex);
                g_stackResolutionStatus = "Symbol resolver could not initialize (Windows error " + std::to_string(error) + ")";
                return;
            }

            std::unordered_map<std::uintptr_t, bool> loadedModules;
            std::unordered_map<std::string, FunctionSamples> functions;
            std::uint64_t frameTotal{};
            for (const auto& [address, count] : g_stackAddressSamples) {
                MEMORY_BASIC_INFORMATION memory{};
                if (!VirtualQuery(reinterpret_cast<const void*>(address), &memory, sizeof(memory)) || memory.Type != MEM_IMAGE || !memory.AllocationBase) continue;
                const auto base = reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
                wchar_t path[32768]{};
                const auto pathLength = GetModuleFileNameW(static_cast<HMODULE>(memory.AllocationBase), path, static_cast<DWORD>(std::size(path)));
                if (!pathLength || pathLength >= std::size(path)) continue;
                const auto separator = std::wstring_view(path, pathLength).find_last_of(L"\\/");
                const auto moduleName = Utf8(path + (separator == std::wstring_view::npos ? 0 : separator + 1));
                if (moduleName.empty()) continue;

                if (!loadedModules.contains(base)) {
                    MODULEINFO moduleInfo{};
                    if (GetModuleInformation(GetCurrentProcess(), static_cast<HMODULE>(memory.AllocationBase), &moduleInfo, sizeof(moduleInfo)))
                        SymLoadModuleExW(symbolProcess, nullptr, path, nullptr, static_cast<DWORD64>(base), moduleInfo.SizeOfImage, nullptr, 0);
                    loadedModules.emplace(base, true);
                }

                std::string functionName;
                DWORD64 displacement{};
                std::vector<std::byte> symbolBuffer(sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(char));
                auto* symbol = reinterpret_cast<SYMBOL_INFO*>(symbolBuffer.data());
                symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
                symbol->MaxNameLen = MAX_SYM_NAME;
                const bool symbolResolved = SymFromAddr(symbolProcess, static_cast<DWORD64>(address), &displacement, symbol) != FALSE;
                if (symbolResolved) functionName = symbol->Name;
                if (functionName.empty()) functionName = moduleName + "+" + HexOffset(address - base);
                auto& entry = functions[moduleName + "!" + functionName];
                entry.module = moduleName;
                entry.name = functionName;
                entry.category = FunctionCategory(moduleName);
                entry.symbolResolved = symbolResolved;
                entry.count += count;
                frameTotal += count;
            }
            SymCleanup(symbolProcess);
            SymSetOptions(previousOptions);
            CloseHandle(symbolProcess);
            std::vector<FunctionSamples> resolved;
            resolved.reserve(functions.size());
            for (auto& [_, function] : functions) resolved.push_back(std::move(function));
            std::sort(resolved.begin(), resolved.end(), [](const auto& a, const auto& b) { return a.count > b.count; });
            std::scoped_lock lock(g_profileMutex);
            g_functionSamples = std::move(resolved);
            g_stackFrameCount = frameTotal;
            g_stackResolutionStatus = "Resolved " + std::to_string(g_functionSamples.size()) + " sampled call-stack entries; local symbols are used when available, otherwise module offsets";
        }

        std::filesystem::path ProfilePath()
        {
            wchar_t documents[MAX_PATH]{};
            if (FAILED(SHGetFolderPathW(nullptr, CSIDL_PERSONAL, nullptr, SHGFP_TYPE_CURRENT, documents)) || !documents[0]) return {};
            return std::filesystem::path(documents) / L"My Games/Skyrim Special Edition/SKSE/SkyMonitor.ini";
        }

        std::string ReadIniString(const std::filesystem::path& path, const wchar_t* section, const wchar_t* key)
        {
            wchar_t value[512]{};
            GetPrivateProfileStringW(section, key, L"", value, static_cast<DWORD>(std::size(value)), path.c_str());
            return Utf8(value);
        }

        void LoadPreviousRun()
        {
            g_previousModuleSamples.clear();
            g_previousSampleCount = 0;
            g_previousFrameTimeMs = -1.0;
            g_previousStarted.clear();
            const auto path = ProfilePath();
            if (path.empty() || !std::filesystem::exists(path)) return;
            g_previousSampleCount = GetPrivateProfileIntW(L"SkyMonitor", L"SampleCount", 0, path.c_str());
            g_previousStarted = ReadIniString(path, L"SkyMonitor", L"Started");
            const auto frameText = ReadIniString(path, L"SkyMonitor", L"FrameTimeAverageMs");
            if (!frameText.empty()) g_previousFrameTimeMs = std::strtod(frameText.c_str(), nullptr);
            const auto moduleCount = std::min<DWORD>(GetPrivateProfileIntW(L"SkyMonitor", L"ModuleCount", 0, path.c_str()), 1000);
            for (DWORD i = 1; i <= moduleCount; ++i) {
                const auto section = L"Module" + std::to_wstring(i);
                const auto name = ReadIniString(path, section.c_str(), L"Name");
                const auto samples = GetPrivateProfileIntW(section.c_str(), L"Samples", 0, path.c_str());
                if (!name.empty() && samples) g_previousModuleSamples[name] = samples;
            }
        }

        std::string FormatTime(const SYSTEMTIME& time)
        {
            char text[40]{};
            std::snprintf(text, sizeof(text), "%04u-%02u-%02u %02u:%02u:%02u.%03u",
                time.wYear, time.wMonth, time.wDay, time.wHour, time.wMinute, time.wSecond, time.wMilliseconds);
            return text;
        }

        std::string Utf8(const wchar_t* text)
        {
            if (!text || !*text) return {};
            const int length = WideCharToMultiByte(CP_UTF8, 0, text, -1, nullptr, 0, nullptr, nullptr);
            if (length <= 1) return {};
            std::string result(static_cast<std::size_t>(length), '\0');
            WideCharToMultiByte(CP_UTF8, 0, text, -1, result.data(), length, nullptr, nullptr);
            result.pop_back();
            return result;
        }

        bool EnableSystemProfilePrivilege(DWORD& error)
        {
            HANDLE token{};
            if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
                error = GetLastError();
                return false;
            }
            LUID privilege{};
            if (!LookupPrivilegeValueW(nullptr, L"SeSystemProfilePrivilege", &privilege)) {
                error = GetLastError();
                CloseHandle(token);
                return false;
            }
            TOKEN_PRIVILEGES requested{};
            requested.PrivilegeCount = 1;
            requested.Privileges[0].Luid = privilege;
            requested.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
            SetLastError(ERROR_SUCCESS);
            const BOOL adjusted = AdjustTokenPrivileges(token, FALSE, &requested, static_cast<DWORD>(sizeof(requested)), nullptr, nullptr);
            error = GetLastError();
            CloseHandle(token);
            return adjusted && error != ERROR_NOT_ALL_ASSIGNED;
        }

        void OnProfileEvent(EVENT_RECORD* event)
        {
            if (!event) return;
            ++g_eventsSeen;
            // TraceStackTracingInfo emits a StackWalk event correlated to the
            // original sample. Its payload is timestamp, originating PID/TID,
            // then pointer-sized instruction addresses. Capture this separate
            // event stream; many Windows builds do not attach stack addresses
            // to the SampledProfile event itself.
            if (IsEqualGUID(event->EventHeader.ProviderId, kStackWalkGuid) &&
                event->EventHeader.EventDescriptor.Opcode == kStackWalkOpcode) {
                ++g_stackWalkEventsSeen;
                const bool is32Bit = (event->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER) != 0;
                const std::size_t addressSize = is32Bit ? sizeof(ULONG) : sizeof(ULONG64);
                constexpr std::size_t stackHeaderSize = sizeof(ULONG64) + sizeof(ULONG) * 2;
                if (event->UserDataLength < stackHeaderSize + addressSize || !event->UserData) return;
                ULONG processId{};
                std::memcpy(&processId, static_cast<const std::byte*>(event->UserData) + sizeof(ULONG64), sizeof(processId));
                if (processId != GetCurrentProcessId()) return;
                ++g_stackWalkMatched;
                const auto* addresses = static_cast<const std::byte*>(event->UserData) + stackHeaderSize;
                const auto frameCount = std::min<std::size_t>((event->UserDataLength - stackHeaderSize) / addressSize, 192);
                std::scoped_lock lock(g_profileMutex);
                for (std::size_t frame = 0; frame < frameCount; ++frame) {
                    std::uintptr_t address{};
                    if (is32Bit) {
                        ULONG value{};
                        std::memcpy(&value, addresses + frame * addressSize, sizeof(value));
                        address = value;
                    } else {
                        ULONG64 value{};
                        std::memcpy(&value, addresses + frame * addressSize, sizeof(value));
                        address = static_cast<std::uintptr_t>(value);
                    }
                    if (!address) continue;
                    const auto found = g_stackAddressSamples.find(address);
                    if (found != g_stackAddressSamples.end()) ++found->second;
                    else if (g_stackAddressSamples.size() < 8000) g_stackAddressSamples.emplace(address, 1);
                }
                return;
            }
            if (event->EventHeader.EventDescriptor.Opcode != kSampledProfileOpcode ||
                (!IsEqualGUID(event->EventHeader.ProviderId, kPerfInfoGuid) &&
                 !IsEqualGUID(event->EventHeader.ProviderId, kSystemTraceControlGuid))) return;
            ++g_profileEventsSeen;

            const std::size_t pointerSize = (event->EventHeader.Flags & EVENT_HEADER_FLAG_32_BIT_HEADER)
                ? sizeof(ULONG) : sizeof(std::uintptr_t);
            if (event->UserDataLength < pointerSize + sizeof(ULONG)) return;

            std::uintptr_t instructionPointer{};
            std::memcpy(&instructionPointer, event->UserData, pointerSize);
            if (!instructionPointer) return;

            // The sampled thread ID is part of the SampledProfile payload.
            // Use it to attribute the sample; kernel event header process IDs
            // are not consistently populated for legacy PerfInfo events.
            ULONG threadId{};
            std::memcpy(&threadId, static_cast<const std::byte*>(event->UserData) + pointerSize, sizeof(threadId));
            const auto processId = GetCurrentProcessId();
            bool belongsToSkyrim = event->EventHeader.ProcessId == processId;
            if (!belongsToSkyrim) {
                const auto thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, threadId);
                if (thread) {
                    belongsToSkyrim = GetProcessIdOfThread(thread) == processId;
                    CloseHandle(thread);
                }
            }
            if (!belongsToSkyrim) return;
            ++g_threadMatched;

            for (USHORT i = 0; i < event->ExtendedDataCount; ++i) {
                const auto& item = event->ExtendedData[i];
                const bool stack64 = item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE64;
                const bool stack32 = item.ExtType == EVENT_HEADER_EXT_TYPE_STACK_TRACE32;
                const auto frameSize = stack64 ? sizeof(ULONG64) : sizeof(ULONG);
                if ((!stack64 && !stack32) || item.DataSize < sizeof(ULONG64) + frameSize) continue;
                const auto* data = reinterpret_cast<const std::byte*>(static_cast<std::uintptr_t>(item.DataPtr));
                const auto payloadBytes = static_cast<std::size_t>(item.DataSize) - sizeof(ULONG64); // MatchId precedes addresses.
                const auto frameCount = std::min<std::size_t>(payloadBytes / frameSize, 64);
                std::scoped_lock lock(g_profileMutex);
                for (std::size_t frame = 0; frame < frameCount; ++frame) {
                    std::uintptr_t frameAddress{};
                    if (stack64) {
                        ULONG64 value{};
                        std::memcpy(&value, data + sizeof(ULONG64) + frame * frameSize, sizeof(value));
                        frameAddress = static_cast<std::uintptr_t>(value);
                    } else {
                        ULONG value{};
                        std::memcpy(&value, data + sizeof(ULONG64) + frame * frameSize, sizeof(value));
                        frameAddress = static_cast<std::uintptr_t>(value);
                    }
                    if (!frameAddress) continue;
                    const auto found = g_stackAddressSamples.find(frameAddress);
                    if (found != g_stackAddressSamples.end()) ++found->second;
                    else if (g_stackAddressSamples.size() < 8000) g_stackAddressSamples.emplace(frameAddress, 1);
                }
                break;
            }

            MEMORY_BASIC_INFORMATION memory{};
            if (!VirtualQuery(reinterpret_cast<const void*>(instructionPointer), &memory, sizeof(memory)) ||
                memory.Type != MEM_IMAGE || !memory.AllocationBase) return;

            const auto base = reinterpret_cast<std::uintptr_t>(memory.AllocationBase);
            {
                std::scoped_lock lock(g_profileMutex);
                const auto cached = g_moduleNames.find(base);
                if (cached != g_moduleNames.end()) {
                    ++g_moduleSamples[cached->second].count;
                    return;
                }
            }

            wchar_t path[32768]{};
            const auto length = GetModuleFileNameW(static_cast<HMODULE>(memory.AllocationBase), path, static_cast<DWORD>(std::size(path)));
            if (!length || length >= std::size(path)) return;
            const auto separator = std::wstring_view(path, length).find_last_of(L"\\/");
            const auto name = Utf8(path + (separator == std::wstring_view::npos ? 0 : separator + 1));
            if (name.empty()) return;
            std::scoped_lock lock(g_profileMutex);
            g_moduleNames.emplace(base, name);
            ++g_moduleSamples[name].count;
        }

        void ProfileWorker()
        {
            DWORD privilegeError{};
            if (!EnableSystemProfilePrivilege(privilegeError)) {
                std::scoped_lock lock(g_profileMutex);
                g_profileStatus = privilegeError == ERROR_NOT_ALL_ASSIGNED || privilegeError == ERROR_PRIVILEGE_NOT_HELD
                    ? "Windows has not granted this account the 'Profile system performance' privilege. An elevated launch may help; otherwise an administrator must grant the user right and you must sign out and back in."
                    : "Could not enable the Windows system profiling privilege (error " + std::to_string(privilegeError) + ").";
                g_profileActive = false;
                return;
            }

            constexpr ULONG nameBytes = sizeof(KERNEL_LOGGER_NAMEW);
            const ULONG propertiesBytes = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
            std::vector<std::byte> propertiesStorage(propertiesBytes);
            auto* properties = reinterpret_cast<EVENT_TRACE_PROPERTIES*>(propertiesStorage.data());
            properties->Wnode.BufferSize = propertiesBytes;
            properties->Wnode.Guid = kSystemTraceControlGuid;
            properties->Wnode.ClientContext = 1;
            properties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
            properties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
            properties->EnableFlags = EVENT_TRACE_FLAG_PROFILE | EVENT_TRACE_FLAG_PROCESS |
                EVENT_TRACE_FLAG_THREAD | EVENT_TRACE_FLAG_IMAGE_LOAD;
            properties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
            std::memcpy(propertiesStorage.data() + properties->LoggerNameOffset, KERNEL_LOGGER_NAMEW, nameBytes);

            TRACEHANDLE session{};
            ULONG error = StartTraceW(&session, KERNEL_LOGGER_NAMEW, properties);
            if (error != ERROR_SUCCESS) {
                std::scoped_lock lock(g_profileMutex);
                if (error == ERROR_ALREADY_EXISTS) {
                    g_profileStatus = "The NT Kernel Logger is already in use by another profiling or tracing tool. Close that capture and retry.";
                } else if (error == ERROR_PRIVILEGE_NOT_HELD) {
                    g_profileStatus = "Windows denied the kernel profiling privilege. Grant 'Profile system performance' to this account, then sign out and back in.";
                } else if (error == ERROR_ACCESS_DENIED) {
                    g_profileStatus = "Windows denied ETW access. Try an elevated Skyrim launch, and check whether another system trace session is active.";
                } else {
                    g_profileStatus = "ETW could not start (Windows error " + std::to_string(error) + ").";
                }
                g_profileActive = false;
                return;
            }
            CLASSIC_EVENT_ID sampledProfileStack{};
            sampledProfileStack.EventGuid = kPerfInfoGuid;
            sampledProfileStack.Type = kSampledProfileOpcode;
            const ULONG stackTraceError = TraceSetInformation(session, TraceStackTracingInfo, &sampledProfileStack, sizeof(sampledProfileStack));
            g_stackCaptureEnabled = stackTraceError == ERROR_SUCCESS;
            g_stackTraceError = stackTraceError;
            if (g_profileStop) {
                ControlTraceW(session, KERNEL_LOGGER_NAMEW, properties, EVENT_TRACE_CONTROL_STOP);
                std::scoped_lock lock(g_profileMutex);
                g_profileStatus = "Deep profiling stopped";
                return;
            }

            EVENT_TRACE_LOGFILEW logfile{};
            logfile.LoggerName = const_cast<LPWSTR>(KERNEL_LOGGER_NAMEW);
            logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            logfile.EventRecordCallback = OnProfileEvent;
            const auto consumer = OpenTraceW(&logfile);
            if (consumer == INVALID_PROCESSTRACE_HANDLE) {
                error = GetLastError();
                ControlTraceW(session, KERNEL_LOGGER_NAMEW, properties, EVENT_TRACE_CONTROL_STOP);
                std::scoped_lock lock(g_profileMutex);
                g_profileStatus = "ETW consumer could not open (Windows error " + std::to_string(error) + ").";
                g_profileActive = false;
                return;
            }

            bool stopRequested = false;
            {
                std::scoped_lock lock(g_profileMutex);
                g_profileSession = session;
                g_profileConsumer = consumer;
                GetLocalTime(&g_profileStartedAt);
                g_profileStoppedAt = {};
                g_stackCaptureStatus = g_stackCaptureEnabled ? "Call-stack capture enabled" : "Call-stack capture unavailable (Windows error " + std::to_string(stackTraceError) + ")";
                g_profileStatus = g_stackCaptureEnabled ? "Sampling Skyrim modules and call stacks" : "Sampling Skyrim modules; call-stack capture unavailable (Windows error " + std::to_string(stackTraceError) + ")";
                stopRequested = g_profileStop.load();
            }
            g_profileActive = true;
            if (stopRequested) ControlTraceW(session, KERNEL_LOGGER_NAMEW, properties, EVENT_TRACE_CONTROL_STOP);
            ProcessTrace(&g_profileConsumer, 1, nullptr, nullptr);
            CloseTrace(consumer);
            ControlTraceW(session, KERNEL_LOGGER_NAMEW, properties, EVENT_TRACE_CONTROL_STOP);
            {
                std::scoped_lock lock(g_profileMutex);
                g_profileSession = 0;
                g_profileConsumer = INVALID_PROCESSTRACE_HANDLE;
                GetLocalTime(&g_profileStoppedAt);
                g_profileStatus = "Resolving sampled call stacks";
            }
            g_profileActive = false;
            ResolveStackFrames();
            {
                std::scoped_lock lock(g_profileMutex);
                g_profileStatus = "Saving SkyMonitor.ini";
            }
            const auto saved = ExportMonitorProfile();
            {
                std::scoped_lock lock(g_profileMutex);
                g_profileStatus = saved.starts_with("Profile automatically saved to ") ? saved : "Deep profiling stopped; automatic save failed: " + saved;
            }
        }
    }

    void StartMonitorDeepProfile()
    {
        std::thread previous;
        {
            std::scoped_lock lock(g_profileMutex);
            if (g_profileActive || g_profileStatus == "Starting ETW session" || g_profileStatus == "Preparing next profile" ||
                g_profileStatus == "Resolving sampled call stacks" || g_profileStatus == "Saving SkyMonitor.ini") return;
            if (g_profileThread.joinable()) previous = std::move(g_profileThread);
            g_profileStop = false;
            g_profileStatus = "Preparing next profile";
        }
        if (previous.joinable()) previous.join();
        LoadPreviousRun();
        std::scoped_lock lock(g_profileMutex);
        g_profileStatus = "Starting ETW session";
        g_moduleSamples.clear();
        g_moduleNames.clear();
        g_stackAddressSamples.clear();
        g_functionSamples.clear();
        g_stackFrameCount = 0;
        g_stackCaptureEnabled = false;
        g_stackTraceError = 0;
        g_stackWalkEventsSeen = 0;
        g_stackWalkMatched = 0;
        g_stackCaptureStatus = "Call-stack capture has not been attempted";
        g_stackResolutionStatus = "Waiting for call-stack samples";
        g_eventsSeen = 0;
        g_profileEventsSeen = 0;
        g_threadMatched = 0;
        g_frameTimeSamples = 0;
        g_frameTimeTotalMs = 0.0;
        g_frameTimeMinMs = 0.0;
        g_frameTimeMaxMs = 0.0;
        g_profileThread = std::thread(ProfileWorker);
    }

    void RecordMonitorProfilerFrameTime(double frameTimeMs)
    {
        if (!g_profileActive.load() || !std::isfinite(frameTimeMs) || frameTimeMs <= 0.0 || frameTimeMs > 10000.0) return;
        std::scoped_lock lock(g_profileMutex);
        if (!g_profileActive.load()) return;
        if (!g_frameTimeSamples) g_frameTimeMinMs = g_frameTimeMaxMs = frameTimeMs;
        else {
            g_frameTimeMinMs = std::min(g_frameTimeMinMs, frameTimeMs);
            g_frameTimeMaxMs = std::max(g_frameTimeMaxMs, frameTimeMs);
        }
        g_frameTimeTotalMs += frameTimeMs;
        ++g_frameTimeSamples;
    }

    void StopMonitorDeepProfile()
    {
        TRACEHANDLE session{};
        {
            std::scoped_lock lock(g_profileMutex);
            g_profileStop = true;
            session = g_profileSession;
        }
        if (session) {
            // StopTrace ends the real-time consumer and lets ProcessTrace return.
            EVENT_TRACE_PROPERTIES properties{};
            properties.Wnode.BufferSize = sizeof(properties);
            ControlTraceW(session, KERNEL_LOGGER_NAMEW, &properties, EVENT_TRACE_CONTROL_STOP);
        }
    }

    std::string GetMonitorProfilerSnapshot()
    {
        std::scoped_lock lock(g_profileMutex);
        std::uint64_t total = 0;
        for (const auto& [_, sample] : g_moduleSamples) total += sample.count;
        std::vector<std::pair<std::string, std::uint64_t>> modules;
        modules.reserve(g_moduleSamples.size());
        for (const auto& [name, sample] : g_moduleSamples) modules.emplace_back(name, sample.count);
        std::sort(modules.begin(), modules.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

        auto escape = [](std::string_view value) {
            std::string out;
            for (const auto ch : value) {
                if (ch == '"' || ch == '\\') out += '\\';
                if (static_cast<unsigned char>(ch) >= 0x20) out += ch;
            }
            return out;
        };
        const bool haveComparison = !g_profileActive.load() && g_previousSampleCount && total;
        std::string json = "{\"active\":" + std::string(g_profileActive.load() ? "true" : "false") +
            ",\"status\":\"" + escape(g_profileStatus) + "\",\"sampleCount\":" + std::to_string(total) +
            ",\"eventsSeen\":" + std::to_string(g_eventsSeen.load()) +
            ",\"profileEventsSeen\":" + std::to_string(g_profileEventsSeen.load()) +
            ",\"threadMatched\":" + std::to_string(g_threadMatched.load()) + ",\"frameTimeSamples\":" + std::to_string(g_frameTimeSamples) +
            ",\"frameTimeAverageMs\":" + (g_frameTimeSamples ? std::to_string(g_frameTimeTotalMs / static_cast<double>(g_frameTimeSamples)) : "null") +
            ",\"stackCaptureEnabled\":" + std::string(g_stackCaptureEnabled ? "true" : "false") + ",\"stackFrameCount\":" + std::to_string(g_stackFrameCount) +
            ",\"stackWalkEventsSeen\":" + std::to_string(g_stackWalkEventsSeen.load()) + ",\"stackWalkMatched\":" + std::to_string(g_stackWalkMatched.load()) +
            ",\"stackCaptureStatus\":\"" + escape(g_stackCaptureStatus) + "\",\"stackResolutionStatus\":\"" + escape(g_stackResolutionStatus) + "\",\"functions\":[";
        for (std::size_t i = 0; i < std::min<std::size_t>(g_functionSamples.size(), 50); ++i) {
            if (i) json += ',';
            const auto& function = g_functionSamples[i];
            const double share = g_stackFrameCount ? 100.0 * static_cast<double>(function.count) / static_cast<double>(g_stackFrameCount) : 0.0;
            json += "{\"module\":\"" + escape(function.module) + "\",\"name\":\"" + escape(function.name) + "\",\"category\":\"" + escape(function.category) + "\",\"symbolResolved\":" + std::string(function.symbolResolved ? "true" : "false") +
                ",\"samples\":" + std::to_string(function.count) + ",\"sharePercent\":" + std::to_string(share) + "}";
        }
        json += "],\"modules\":[";
        const auto count = std::min<std::size_t>(modules.size(), 100);
        for (std::size_t i = 0; i < count; ++i) {
            if (i) json += ',';
            const auto share = total ? 100.0 * static_cast<double>(modules[i].second) / static_cast<double>(total) : 0.0;
            json += "{\"name\":\"" + escape(modules[i].first) + "\",\"samples\":" + std::to_string(modules[i].second) +
                ",\"sharePercent\":" + std::to_string(share) + "}";
        }
        json += "],\"comparison\":{\"available\":" + std::string(haveComparison ? "true" : "false");
        if (haveComparison) {
            const auto currentAverage = g_frameTimeSamples ? g_frameTimeTotalMs / static_cast<double>(g_frameTimeSamples) : -1.0;
            json += ",\"previousStarted\":\"" + escape(g_previousStarted) + "\",\"currentStarted\":\"" + escape(FormatTime(g_profileStartedAt)) +
                "\",\"previousSampleCount\":" + std::to_string(g_previousSampleCount) + ",\"currentSampleCount\":" + std::to_string(total) +
                ",\"previousFrameTimeMs\":" + (g_previousFrameTimeMs >= 0 ? std::to_string(g_previousFrameTimeMs) : "null") +
                ",\"currentFrameTimeMs\":" + (currentAverage >= 0 ? std::to_string(currentAverage) : "null") +
                ",\"frameTimeDeltaMs\":" + (g_previousFrameTimeMs >= 0 && currentAverage >= 0 ? std::to_string(currentAverage - g_previousFrameTimeMs) : "null") + ",\"modules\":[";
            std::vector<std::pair<std::string, double>> changes;
            for (const auto& [name, oldSamples] : g_previousModuleSamples) {
                const auto found = g_moduleSamples.find(name);
                const auto currentSamples = found == g_moduleSamples.end() ? 0 : found->second.count;
                const double oldShare = 100.0 * static_cast<double>(oldSamples) / static_cast<double>(g_previousSampleCount);
                const double newShare = total ? 100.0 * static_cast<double>(currentSamples) / static_cast<double>(total) : 0.0;
                changes.emplace_back(name, newShare - oldShare);
            }
            for (const auto& [name, current] : g_moduleSamples) {
                if (g_previousModuleSamples.contains(name)) continue;
                changes.emplace_back(name, 100.0 * static_cast<double>(current.count) / static_cast<double>(total));
            }
            std::sort(changes.begin(), changes.end(), [](const auto& a, const auto& b) { return std::abs(a.second) > std::abs(b.second); });
            for (std::size_t i = 0; i < std::min<std::size_t>(changes.size(), 8); ++i) {
                if (i) json += ',';
                const auto& name = changes[i].first;
                const auto oldFound = g_previousModuleSamples.find(name);
                const auto newFound = g_moduleSamples.find(name);
                const auto oldSamples = oldFound == g_previousModuleSamples.end() ? 0 : oldFound->second;
                const auto newSamples = newFound == g_moduleSamples.end() ? 0 : newFound->second.count;
                const double oldShare = 100.0 * static_cast<double>(oldSamples) / static_cast<double>(g_previousSampleCount);
                const double newShare = 100.0 * static_cast<double>(newSamples) / static_cast<double>(total);
                json += "{\"name\":\"" + escape(name) + "\",\"previousShare\":" + std::to_string(oldShare) +
                    ",\"currentShare\":" + std::to_string(newShare) + ",\"shareDelta\":" + std::to_string(newShare - oldShare) + "}";
            }
            json += "]";
        }
        json += "}}";
        return json;
    }

    std::string ExportMonitorProfile()
    {
        std::scoped_lock lock(g_profileMutex);
        std::uint64_t total = 0;
        for (const auto& [_, sample] : g_moduleSamples) total += sample.count;
        if (total == 0) return "No profiler samples to export yet. Run the profiler first.";

        const auto outputPath = ProfilePath();
        if (outputPath.empty()) return "Could not locate the current user's Documents folder.";
        std::error_code directoryError;
        std::filesystem::create_directories(outputPath.parent_path(), directoryError);
        if (directoryError) return "Could not create the SkyMonitor output folder: " + directoryError.message();

        if (std::filesystem::exists(outputPath)) {
            auto previousPath = outputPath.parent_path() / L"SkyMonitor_Previous.ini";
            std::error_code backupError;
            std::filesystem::copy_file(outputPath, previousPath, std::filesystem::copy_options::overwrite_existing, backupError);
            if (backupError) return "Could not preserve the previous run before saving: " + backupError.message();
        }

        std::vector<std::pair<std::string, std::uint64_t>> modules;
        modules.reserve(g_moduleSamples.size());
        for (const auto& [name, sample] : g_moduleSamples) modules.emplace_back(name, sample.count);
        std::sort(modules.begin(), modules.end(), [](const auto& a, const auto& b) { return a.second > b.second; });

        std::ofstream file(outputPath, std::ios::binary | std::ios::trunc);
        if (!file) return "Could not write the SkyMonitor profile file.";
        file << "[SkyMonitor]\n"
             << "FormatVersion=2\n"
             << "Active=" << (g_profileActive.load() ? "true" : "false") << "\n"
             << "Started=" << FormatTime(g_profileStartedAt) << "\n"
             << "Stopped=" << (g_profileStoppedAt.wYear ? FormatTime(g_profileStoppedAt) : "still running") << "\n"
             << "SampleCount=" << total << "\n"
             << "ETWEvents=" << g_eventsSeen.load() << "\n"
             << "ProfileEvents=" << g_profileEventsSeen.load() << "\n"
             << "SkyrimThreadSamples=" << g_threadMatched.load() << "\n"
             << "StackCaptureEnabled=" << (g_stackCaptureEnabled ? "true" : "false") << "\n"
             << "StackCaptureStatus=" << g_stackCaptureStatus << "\n"
             << "StackCaptureError=" << g_stackTraceError << "\n"
             << "StackWalkEventsSeen=" << g_stackWalkEventsSeen.load() << "\n"
             << "StackWalkMatched=" << g_stackWalkMatched.load() << "\n"
             << "StackFrameCount=" << g_stackFrameCount << "\n"
             << "StackResolutionStatus=" << g_stackResolutionStatus << "\n"
             << "FunctionCount=" << g_functionSamples.size() << "\n"
             << "FrameTimeSamples=" << g_frameTimeSamples << "\n"
             << "FrameTimeAverageMs=" << (g_frameTimeSamples ? g_frameTimeTotalMs / static_cast<double>(g_frameTimeSamples) : 0.0) << "\n"
             << "FrameTimeMinimumMs=" << (g_frameTimeSamples ? g_frameTimeMinMs : 0.0) << "\n"
             << "FrameTimeMaximumMs=" << (g_frameTimeSamples ? g_frameTimeMaxMs : 0.0) << "\n"
             << "ModuleCount=" << modules.size() << "\n"
             << "AttributionNote=Module shares are sampled CPU estimates, not exact CPU time or ESP plugin costs.\n\n";

        file << "[ProfilerFunctions]\nCount=" << g_functionSamples.size() << "\n\n";
        for (std::size_t i = 0; i < g_functionSamples.size(); ++i) {
            const auto& function = g_functionSamples[i];
            const auto share = g_stackFrameCount ? 100.0 * static_cast<double>(function.count) / static_cast<double>(g_stackFrameCount) : 0.0;
            file << "[Function" << (i + 1) << "]\n"
                 << "Module=" << function.module << "\n"
                 << "Name=" << function.name << "\n"
                 << "Category=" << function.category << "\n"
                 << "SymbolResolved=" << (function.symbolResolved ? "true" : "false") << "\n"
                 << "InclusiveStackHits=" << function.count << "\n"
                 << "SharePercent=" << share << "\n\n";
        }

        file << std::fixed << std::setprecision(4);
        for (std::size_t i = 0; i < modules.size(); ++i) {
            const auto share = 100.0 * static_cast<double>(modules[i].second) / static_cast<double>(total);
            file << "[Module" << (i + 1) << "]\n"
                 << "Name=" << modules[i].first << "\n"
                 << "Samples=" << modules[i].second << "\n"
                 << "SharePercent=" << share << "\n\n";
        }
        file.close();
        if (!file) return "SkyMonitor profile export failed while writing the file.";
        return "Profile automatically saved to " + outputPath.string();
    }
}
