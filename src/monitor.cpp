#include "monitor.h"

#include <SKSE/SKSE.h>
#include <RE/T/TESDataHandler.h>
#include <RE/S/State.h>
#include <RE/V/VirtualMachine.h>
#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <Pdh.h>
#include <PdhMsg.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <limits>
#include <unordered_map>
#include <utility>
#include <vector>

#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Pdh.lib")

namespace SkyOS {
    namespace {
        struct LoadedPluginInfo {
            std::string name;
            std::string type;
            std::string loadOrderIndex;
            std::uint32_t loadOrderPosition{};
            bool light{};
            std::uint32_t recordCount{};
            std::uint32_t fileSizeBytes{};
            std::uint64_t fileLastWriteTime{};
        };

        LoadedPluginInfo DescribePlugin(const RE::TESFile* plugin, std::uint32_t loadOrderPosition)
        {
            LoadedPluginInfo info;
            if (!plugin) return info;
            info.loadOrderPosition = loadOrderPosition;
            const auto filename = plugin->GetFilename();
            info.name.assign(filename);
            const auto dot = filename.find_last_of('.');
            if (dot != std::string_view::npos) {
                info.type.assign(filename.substr(dot + 1));
                std::transform(info.type.begin(), info.type.end(), info.type.begin(), [](unsigned char ch) { return static_cast<char>(std::toupper(ch)); });
            }
            info.light = plugin->IsLight();
            char index[24]{};
            if (info.light) std::snprintf(index, sizeof(index), "FE:%03X", plugin->GetSmallFileCompileIndex());
            else std::snprintf(index, sizeof(index), "%02X", plugin->GetCompileIndex());
            info.loadOrderIndex = index;
            info.recordCount = plugin->formCount;
            info.fileSizeBytes = plugin->filesize;
            info.fileLastWriteTime = static_cast<std::uint64_t>(plugin->fileData.lastWriteTime);
            return info;
        }

        std::string FormatFileSize(std::uint32_t bytes)
        {
            char size[32]{};
            if (bytes >= 1024u * 1024u) std::snprintf(size, sizeof(size), "%.1f MB", static_cast<double>(bytes) / (1024.0 * 1024.0));
            else if (bytes >= 1024u) std::snprintf(size, sizeof(size), "%.1f KB", static_cast<double>(bytes) / 1024.0);
            else std::snprintf(size, sizeof(size), "%u B", bytes);
            return size;
        }

        std::string JsonEscape(std::string_view text)
        {
            std::string out;
            out.reserve(text.size() + 8);
            for (const unsigned char ch : text) {
                switch (ch) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default: if (ch >= 0x20) out += static_cast<char>(ch); break;
                }
            }
            return out;
        }

        struct GpuCounters {
            PDH_HQUERY query{};
            PDH_HCOUNTER engine{};
            PDH_HCOUNTER memory{};
            bool initialized{};

            ~GpuCounters() { if (query) PdhCloseQuery(query); }

            bool Init()
            {
                if (initialized) return query != nullptr;
                initialized = true;
                if (PdhOpenQueryW(nullptr, 0, &query) != ERROR_SUCCESS) return false;
                const auto engineStatus = PdhAddEnglishCounterW(query, L"\\GPU Engine(*)\\Utilization Percentage", 0, &engine);
                const auto memoryStatus = PdhAddEnglishCounterW(query, L"\\GPU Process Memory(*)\\Dedicated Usage", 0, &memory);
                if (engineStatus != ERROR_SUCCESS) engine = nullptr;
                if (memoryStatus != ERROR_SUCCESS) memory = nullptr;
                return engine || memory;
            }

            static bool Read(PDH_HCOUNTER counter, DWORD pid, double& total)
            {
                if (!counter) return false;
                DWORD bytes = 0, count = 0;
                auto status = PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &bytes, &count, nullptr);
                if (status != PDH_MORE_DATA || bytes == 0) return false;
                std::vector<std::byte> storage(bytes);
                auto* values = reinterpret_cast<PPDH_FMT_COUNTERVALUE_ITEM_W>(storage.data());
                status = PdhGetFormattedCounterArrayW(counter, PDH_FMT_DOUBLE, &bytes, &count, values);
                if (status != ERROR_SUCCESS) return false;
                const std::wstring marker = L"pid_" + std::to_wstring(pid) + L"_";
                total = 0.0;
                bool found = false;
                for (DWORD i = 0; i < count; ++i) {
                    if (!values[i].szName || std::wstring_view(values[i].szName).find(marker) == std::wstring_view::npos) continue;
                    if (values[i].FmtValue.CStatus != ERROR_SUCCESS || !std::isfinite(values[i].FmtValue.doubleValue)) continue;
                    total += std::max(0.0, values[i].FmtValue.doubleValue);
                    found = true;
                }
                return found;
            }

            bool Sample(DWORD pid, double& gpu, std::uint64_t& vram)
            {
                if (!Init()) return false;
                if (PdhCollectQueryData(query) != ERROR_SUCCESS) return false;
                double gpuValue = 0, memoryValue = 0;
                const bool hasGpu = Read(engine, pid, gpuValue);
                const bool hasMemory = Read(memory, pid, memoryValue);
                if (hasGpu) gpu = std::clamp(gpuValue, 0.0, 100.0);
                if (hasMemory) vram = static_cast<std::uint64_t>(memoryValue);
                return hasGpu || hasMemory;
            }
        };

        double ProcessCpuPercent()
        {
            static ULONGLONG previousWall = 0;
            static ULONGLONG previousProcess = 0;
            FILETIME creation{}, exit{}, kernel{}, user{}, wall{};
            const HANDLE process = GetCurrentProcess();
            GetSystemTimeAsFileTime(&wall);
            if (!GetProcessTimes(process, &creation, &exit, &kernel, &user)) return -1.0;
            ULARGE_INTEGER nowWall{}, nowKernel{}, nowUser{};
            nowWall.LowPart = wall.dwLowDateTime; nowWall.HighPart = wall.dwHighDateTime;
            nowKernel.LowPart = kernel.dwLowDateTime; nowKernel.HighPart = kernel.dwHighDateTime;
            nowUser.LowPart = user.dwLowDateTime; nowUser.HighPart = user.dwHighDateTime;
            const auto nowProcess = nowKernel.QuadPart + nowUser.QuadPart;
            if (!previousWall || nowWall.QuadPart <= previousWall || nowProcess < previousProcess) {
                previousWall = nowWall.QuadPart; previousProcess = nowProcess; return -1.0;
            }
            const auto wallDelta = nowWall.QuadPart - previousWall;
            const auto processDelta = nowProcess - previousProcess;
            previousWall = nowWall.QuadPart; previousProcess = nowProcess;
            SYSTEM_INFO system{}; GetSystemInfo(&system);
            const auto cores = std::max<DWORD>(1, system.dwNumberOfProcessors);
            return std::clamp(100.0 * static_cast<double>(processDelta) / static_cast<double>(wallDelta) / cores, 0.0, 100.0);
        }

        double GameFramesPerSecond()
        {
            auto* gameState = RE::BSGraphics::State::GetSingleton();
            if (!gameState) return -1.0;

            LARGE_INTEGER now{};
            LARGE_INTEGER frequency{};
            if (!QueryPerformanceCounter(&now) || !QueryPerformanceFrequency(&frequency) || frequency.QuadPart <= 0) return -1.0;

            static std::uint32_t previousFrames = 0;
            static LONGLONG previousTime = 0;
            const auto frames = gameState->GetFrameCount();
            if (previousTime == 0 || now.QuadPart <= previousTime) {
                previousFrames = frames;
                previousTime = now.QuadPart;
                return -1.0;
            }

            const auto elapsed = static_cast<double>(now.QuadPart - previousTime) / static_cast<double>(frequency.QuadPart);
            const auto frameDelta = static_cast<std::uint32_t>(frames - previousFrames);
            previousFrames = frames;
            previousTime = now.QuadPart;
            if (elapsed <= 0.0 || elapsed > 10.0) return -1.0;
            return std::clamp(static_cast<double>(frameDelta) / elapsed, 0.0, 1000.0);
        }

        struct ThreadUsage {
            double mainThreadPercent{ -1.0 };
            double workerThreadsPercent{ -1.0 };
            std::uint32_t threadCount{};
        };

        ThreadUsage SampleThreadUsage()
        {
            struct Times { ULONGLONG cpu{}; ULONGLONG created{}; };
            static std::unordered_map<DWORD, Times> previous;
            static ULONGLONG previousWall = 0;
            const auto now = GetTickCount64();
            const auto elapsedMs = previousWall && now > previousWall ? now - previousWall : 0;
            previousWall = now;

            ThreadUsage result;
            const HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if (snapshot == INVALID_HANDLE_VALUE) return result;
            std::unordered_map<DWORD, Times> current;
            ULONGLONG mainCreated = std::numeric_limits<ULONGLONG>::max();
            DWORD mainThreadId = 0;
            THREADENTRY32 entry{};
            entry.dwSize = sizeof(entry);
            if (Thread32First(snapshot, &entry)) {
                do {
                    if (entry.th32OwnerProcessID != GetCurrentProcessId()) continue;
                    ++result.threadCount;
                    const HANDLE thread = OpenThread(THREAD_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ThreadID);
                    if (!thread) continue;
                    FILETIME created{}, exited{}, kernel{}, user{};
                    if (GetThreadTimes(thread, &created, &exited, &kernel, &user)) {
                        ULARGE_INTEGER c{}, k{}, u{};
                        c.LowPart = created.dwLowDateTime; c.HighPart = created.dwHighDateTime;
                        k.LowPart = kernel.dwLowDateTime; k.HighPart = kernel.dwHighDateTime;
                        u.LowPart = user.dwLowDateTime; u.HighPart = user.dwHighDateTime;
                        current.emplace(entry.th32ThreadID, Times{ k.QuadPart + u.QuadPart, c.QuadPart });
                        if (c.QuadPart < mainCreated) {
                            mainCreated = c.QuadPart;
                            mainThreadId = entry.th32ThreadID;
                        }
                    }
                    CloseHandle(thread);
                } while (Thread32Next(snapshot, &entry));
            }
            CloseHandle(snapshot);

            if (elapsedMs) {
                const double wallUnits = static_cast<double>(elapsedMs) * 10000.0;
                double worker = 0.0;
                bool hasSamples = false;
                for (const auto& [threadId, times] : current) {
                    const auto old = previous.find(threadId);
                    if (old == previous.end() || times.cpu < old->second.cpu) continue;
                    const double percent = 100.0 * static_cast<double>(times.cpu - old->second.cpu) / wallUnits;
                    if (threadId == mainThreadId) result.mainThreadPercent = std::clamp(percent, 0.0, 100.0);
                    else worker += percent;
                    hasSamples = true;
                }
                if (hasSamples) result.workerThreadsPercent = worker;
            }
            previous = std::move(current);
            return result;
        }

        std::string NumberOrNull(double value)
        {
            return value < 0 || !std::isfinite(value) ? "null" : std::to_string(value);
        }
    }

    std::string GetMonitorSnapshot(bool includePlugins, bool includeProfiler)
    {
        double cpu = ProcessCpuPercent();
        std::uint64_t ram = 0;
        PROCESS_MEMORY_COUNTERS_EX memory{};
        memory.cb = sizeof(memory);
        const bool hasProcessMemory = GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&memory), sizeof(memory)) != FALSE;
        if (hasProcessMemory) {
            ram = memory.WorkingSetSize;
        }
        static ULONGLONG previousPrivateBytes = 0;
        static ULONGLONG previousMemorySample = 0;
        double privateGrowthBytesPerSecond = -1.0;
        bool hasMemoryGrowthSample = false;
        const auto memorySampleTime = GetTickCount64();
        if (hasProcessMemory && previousMemorySample && memorySampleTime > previousMemorySample) {
            const auto elapsedSeconds = static_cast<double>(memorySampleTime - previousMemorySample) / 1000.0;
            privateGrowthBytesPerSecond = (static_cast<double>(memory.PrivateUsage) - static_cast<double>(previousPrivateBytes)) / elapsedSeconds;
            hasMemoryGrowthSample = true;
        }
        if (hasProcessMemory) {
            previousPrivateBytes = memory.PrivateUsage;
            previousMemorySample = memorySampleTime;
        }
        MEMORYSTATUSEX systemMemory{};
        systemMemory.dwLength = sizeof(systemMemory);
        const bool hasSystemMemory = GlobalMemoryStatusEx(&systemMemory) != FALSE;
        double gpu = -1;
        const double fps = GameFramesPerSecond();
        SkyOS::RecordMonitorProfilerFrameTime(fps > 0 ? 1000.0 / fps : -1.0);
        const auto threads = SampleThreadUsage();
        std::uint64_t vram = 0;
        static GpuCounters counters;
        const bool hasGpu = counters.Sample(GetCurrentProcessId(), gpu, vram);

        std::vector<LoadedPluginInfo> plugins;
        std::size_t pluginCount = 0;
        std::string scriptCount = "null";
        if (auto* vm = RE::BSScript::Internal::VirtualMachine::GetSingleton()) {
            std::size_t attachedScriptCount = 0;
            RE::BSSpinLockGuard lock(vm->attachedScriptsLock);
            for (const auto& entry : vm->attachedScripts) {
                attachedScriptCount += entry.second.size();
            }
            scriptCount = std::to_string(attachedScriptCount);
        }
        if (const auto* handler = RE::TESDataHandler::GetSingleton()) {
            const auto fullCount = handler->GetLoadedModCount();
            const auto lightCount = handler->GetLoadedLightModCount();
            pluginCount = static_cast<std::size_t>(fullCount) + lightCount;
            if (includePlugins) {
                const auto* fullPlugins = handler->GetLoadedMods();
                const auto* lightPlugins = handler->GetLoadedLightMods();
                plugins.reserve(pluginCount);
                if (fullPlugins) {
                    for (std::size_t i = 0; i < fullCount; ++i) {
                        if (fullPlugins[i]) plugins.emplace_back(DescribePlugin(fullPlugins[i], static_cast<std::uint32_t>(i)));
                    }
                }
                // Skyrim stores ESL/light plugins in a separate collection.
                if (lightPlugins) {
                    for (std::size_t i = 0; i < lightCount; ++i) {
                        if (lightPlugins[i]) plugins.emplace_back(DescribePlugin(lightPlugins[i], static_cast<std::uint32_t>(fullCount + i)));
                    }
                }
            }
        }

        std::string result = "{\"cpuPercent\":" + NumberOrNull(cpu) +
            ",\"ramBytes\":" + (ram ? std::to_string(ram) : "null") +
            ",\"gpuPercent\":" + NumberOrNull(hasGpu ? gpu : -1.0) +
            ",\"vramBytes\":" + (hasGpu && vram ? std::to_string(vram) : "null") +
            ",\"fps\":" + NumberOrNull(fps) + ",\"pluginCount\":" + std::to_string(pluginCount) +
            ",\"privateBytes\":" + (memory.PrivateUsage ? std::to_string(memory.PrivateUsage) : "null") +
            ",\"privateGrowthBytesPerSecond\":" + (hasMemoryGrowthSample && std::isfinite(privateGrowthBytesPerSecond) ? std::to_string(privateGrowthBytesPerSecond) : "null") +
            ",\"systemRamBytes\":" + (hasSystemMemory ? std::to_string(systemMemory.ullTotalPhys) : "null") +
            ",\"mainThreadCpuPercent\":" + NumberOrNull(threads.mainThreadPercent) +
            ",\"workerThreadsCpuPercent\":" + NumberOrNull(threads.workerThreadsPercent) +
            ",\"threadCount\":" + std::to_string(threads.threadCount) +
            ",\"frameTimeMs\":" + NumberOrNull(fps > 0 ? 1000.0 / fps : -1.0) +
            ",\"scriptCount\":" + scriptCount + ",\"plugins\":[";
        for (std::size_t i = 0; i < plugins.size(); ++i) {
            if (i) result += ',';
            const auto& plugin = plugins[i];
            result += "{\"name\":\"" + JsonEscape(plugin.name) + "\",\"type\":\"" + JsonEscape(plugin.type) +
                "\",\"loadOrderIndex\":\"" + JsonEscape(plugin.loadOrderIndex) + "\",\"loadOrderPosition\":" + std::to_string(plugin.loadOrderPosition) + ",\"lightPlugin\":" + std::string(plugin.light ? "true" : "false") +
                ",\"recordCount\":" + std::to_string(plugin.recordCount) + ",\"fileSizeBytes\":" + std::to_string(plugin.fileSizeBytes) +
                ",\"fileLastWriteTime\":" + std::to_string(plugin.fileLastWriteTime) +
                ",\"fileSize\":\"" + FormatFileSize(plugin.fileSizeBytes) + "\",\"ramAttribution\":\"Shared/unattributed\"}";
        }
        result += "],\"profiler\":" + (includeProfiler ? GetMonitorProfilerSnapshot() : "null") + "}";
        return result;
    }
}
