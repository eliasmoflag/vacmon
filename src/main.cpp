#include <Windows.h>
#include <cstdint>
#include <cstddef>
#include "hooks.hpp"

std::int32_t WINAPI DllMain(
    std::uintptr_t image_base,
    std::uint32_t reason_for_call,
    std::size_t) {

    if (reason_for_call == DLL_PROCESS_ATTACH) {

        vacmon::hooks::install();
    }

	return TRUE;
}
