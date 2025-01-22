#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include "hooks.hpp"

static std::int32_t WINAPI DllMain(
    std::uintptr_t image_base,
    std::uint32_t reason_for_call,
    std::size_t reserved) {

    switch (reason_for_call) {
    case DLL_PROCESS_ATTACH:
        if (!vacmon::hooks::get().install()) {
            return FALSE;
        }
        break;
    case DLL_PROCESS_DETACH:
        if (reserved == 0 && !vacmon::hooks::get().uninstall()) {
            return FALSE;
        }
        break;
    }

	return TRUE;
}
