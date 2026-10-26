# SkyMonitor

## Features

- Shows live Skyrim process telemetry and loaded-plugin information in the SkyOS interface.
- Provides an optional deep profile that samples runtime activity, resolves collected call stacks, and exports a report for later inspection.
- Lets players choose a 1500–5000 ms refresh interval and loaded-plugin display in SkyViewer. The numeric field shows its limits and accepts typed values in range. Profiling remains an explicit player action.

## Changelog

- **Standalone app module:** monitoring and profiler code ships in `SkyMonitor.dll`; its page, branding, settings module, and guide ship in the SkyMonitor package.
- **Existing behavior retained:** live snapshots, plugin overview, and on-demand deep profiling remain accessible from the SkyOS Home page.

## Requirements

- Skyrim Special Edition / Anniversary Edition Latest Version (supported runtime).
- SKSE Latest Version.
- PrismaUI Latest Version.
- SkyOS Latest Version.

## Files and saved data

- Module page and settings schema: `Data/SKSE/Plugins/SkyOS/Mods/SkyViewer/SkyMonitor/`.
- SkyDocuments guide: `Data/SKSE/Plugins/SkyOS/Mods/SkyMonitor/SkyDocuments/`.
- Per-user module settings: `%LOCALAPPDATA%/SkyOS/SkyViewer/SkyMonitor/settings.json`.
- Profile exports and the profiler's small resume state are stored under `%USERPROFILE%/Documents/My Games/Skyrim Special Edition/SKSE/` (the profiler configuration is `SkyMonitor.ini`).

