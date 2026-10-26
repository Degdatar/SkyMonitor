#pragma once

#include <string>

#if defined(SKYOS_SKYMONITOR_EXPORTS)
#define SKYOS_SKYMONITOR_API __declspec(dllexport)
#else
#define SKYOS_SKYMONITOR_API __declspec(dllimport)
#endif

namespace SkyOS {
    // Omit heavy plugin and profiler payloads outside their dedicated dashboard tabs.
    [[nodiscard]] SKYOS_SKYMONITOR_API std::string GetMonitorSnapshot(bool includePlugins = false, bool includeProfiler = false);
    SKYOS_SKYMONITOR_API void StartMonitorDeepProfile();
    SKYOS_SKYMONITOR_API void StopMonitorDeepProfile();
    SKYOS_SKYMONITOR_API void RecordMonitorProfilerFrameTime(double frameTimeMs);
    [[nodiscard]] SKYOS_SKYMONITOR_API std::string GetMonitorProfilerSnapshot();
    [[nodiscard]] SKYOS_SKYMONITOR_API std::string ExportMonitorProfile();
}
