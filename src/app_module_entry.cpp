#include <SKSE/SKSE.h>

#include <Windows.h>

#if defined(SKYOS_SKYREWRITE_EXPORTS)
#include "skyrewrite.h"
#endif

namespace {
    void OnMessage(SKSE::MessagingInterface::Message* message)
    {
        if (!message || message->type != SKSE::MessagingInterface::kDataLoaded) return;
        if (!GetModuleHandleW(L"SkyOS.dll")) {
            SKSE::log::critical("This SkyOS app module requires SkyOS.dll. The app will remain inactive until the SkyOS core is installed.");
            return;
        }
#if defined(SKYOS_SKYMISSIONS_EXPORTS)
        if (!GetModuleHandleW(L"SkyRewrite.dll")) {
            SKSE::log::critical("SkyMissions requires SkyRewrite.dll for gameplay-event mission tracking. Install and load SkyRewrite; SkyOS Core remains independent.");
            return;
        }
#endif
#if defined(SKYOS_SKYREWRITE_EXPORTS)
        SkyOS::RegisterSkyRewriteSerialization();
        SkyOS::InstallSkyRewriteEventSinks();
#endif
        SKSE::log::info("SkyOS core detected; app module is ready.");
    }
}

SKSE_PLUGIN_LOAD(const SKSE::LoadInterface* skse)
{
    SKSE::Init(skse);
    auto* messaging = SKSE::GetMessagingInterface();
    if (!messaging || !messaging->RegisterListener("SKSE", OnMessage)) {
        SKSE::log::critical("SkyOS app module could not register its SKSE message listener");
        return false;
    }
    return true;
}
