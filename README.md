# SkyMonitor

SkyMonitor is a Skyrim SE/AE telemetry and profiling module for SkyOS. It reports live process-level measurements, shows the loaded plugin list, and offers an explicit opt-in deep profiler.

## Features

- Skyrim process CPU usage, working-set and private memory, thread CPU, system RAM, FPS, and frame time.
- GPU engine utilization and dedicated video memory when Windows exposes the relevant performance counters.
- Loaded game-plugin inventory with load-order index and plugin metadata.
- Optional Windows ETW deep profiling with sampled native module and call-stack attribution, plus profile export.
- SkyViewer settings for refresh interval, plugin-list visibility, and the open-hotkey preference.

Resource measurements are reported for the shared Skyrim process or GPU engine. They are not exact resource-cost measurements for individual ESP/ESM plugins. Deep-profiler module shares are estimates from collected samples, not exact CPU time.

## Requirements

- Windows x64 and Visual Studio 2022 with the C++ desktop workload.
- CMake 3.24 or newer.
- Git, for fetching CommonLibSSE-NG.
- vcpkg with `VCPKG_ROOT` set, using the `x64-windows-static-md` triplet.
- Skyrim AE, SKSE, PrismaUI, and the matching SkyOS core at runtime.

Deep profiling uses Windows ETW and requires the **Profile system performance** privilege. SkyMonitor attempts to enable the privilege for the current process. If Windows has not granted it to the account, an administrator must assign it and the user must sign out and back in. Another profiler may already own the single NT Kernel Logger session.

## Build

From this directory, configure and build the Release preset:

```powershell
cmake --preset release
cmake --build --preset release --parallel
```

Create an archive of the install tree:

```powershell
cpack --config build/CPackConfig.cmake -G 7Z -C Release
```

The install tree contains the DLL and SkyMonitor-owned resources under Skyrim's `Data` directory structure. CPack defaults to ZIP; the command above selects 7-Zip when the CPack 7Z generator is available on the machine.

## SkyOS integration

SkyMonitor is an optional native app module. `SkyOS.dll` owns the shared PrismaUI shell, dashboard, request listeners, and settings bridge. The core checks for `SkyMonitor.dll` and calls its exported monitoring and profiler functions. The module's SKSE entry checks for `SkyOS.dll` at data load and remains inactive if the core is missing.

Building or installing this repository alone does not provide the shared SkyOS shell. Install the matching SkyOS core and PrismaUI as well.

## Repository layout

```text
src/                         Native telemetry and profiler plugin
data/PrismaUI/views/          SkyMonitor page assets and app artwork
data/SKSE/Plugins/SkyOS/Mods/ SkyMonitor app metadata and SkyDocuments guides
                             SkyViewer module page and settings schema
```

The SkyDocuments source guides are:

- `data/SKSE/Plugins/SkyOS/Mods/SkyMonitor/SkyDocuments/SkyMonitor.html`
- `data/SKSE/Plugins/SkyOS/Mods/SkyMonitor/SkyDocuments/SkyMonitor Module.md`

CMake installs these guides to `Data/SKSE/Plugins/SkyOS/Mods/SkyMonitor/SkyDocuments/`.

## Settings and saved data

SkyViewer → Modules → SkyMonitor provides these settings:

| Setting | Default | Range |
| --- | ---: | ---: |
| Open hotkey | F10 | Key binding preference |
| Refresh interval | 2,000 ms | 1,500–5,000 ms |
| Show loaded plugin list | On | On or off |

Per-user settings are stored at `%LOCALAPPDATA%/SkyOS/SkyViewer/SkyMonitor/settings.json`. Profile exports and resume details use `%USERPROFILE%/Documents/My Games/Skyrim Special Edition/SKSE/`; the profiler configuration file is `SkyMonitor.ini`.
