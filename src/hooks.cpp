#include <Windows.h>
#include <ShlObj.h>
#include <intrin.h>
#include <MinHook.h>
#include <xscan.hpp>
#include <fstream>
#include <iostream>
#include <filesystem>
#include "steam/client_module_manager.hpp"
#include "logger.hpp"
#include "utils.hpp"
#include "hooks.hpp"

vacmon::hooks& vacmon::hooks::get() {
    static vacmon::hooks instance;
    return instance;
}

bool vacmon::hooks::install() {

    m_logger = std::make_unique<logger>("vacmon");

    const auto console_output{ GetStdHandle(STD_OUTPUT_HANDLE) };
    if (DWORD console_mode{ 0 }; GetConsoleMode(console_output, &console_mode)) {
        SetConsoleMode(console_output, console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    m_logger->info("initializing...\n");

    const auto steamservice_dll{ reinterpret_cast<std::uint8_t*>(GetModuleHandleA("steamservice.dll")) };
    const auto p_load_image{ xscan::pattern{ "E8 ? ? ? ? 84 C0 75 16 8B 43 10" }
        .scan(xscan::pe_sections(steamservice_dll)).add(1).rip() };

    if (!p_load_image) {
        m_logger->error("failed to find load_image");
        return false;
    }

    const auto p_protect_image{ xscan::pattern{ "E8 ? ? ? ? 8B 46 08 83 C4 04 8B 40 28" }
        .scan(xscan::pe_sections(steamservice_dll)).add(1).rip() };

    if (!p_protect_image) {
        m_logger->error("failed to find protect_image");
        return false;
    }

    m_logger->info("load_image: {}", utils::format_address(p_load_image));
    m_logger->info("protect_image: {}", utils::format_address(p_protect_image));

    if (MH_Initialize() != MH_OK) {
        m_logger->error("failed to initialize minhook");
        return false;
    }

    if (MH_CreateHook(p_load_image, &load_image, reinterpret_cast<LPVOID*>(&m_load_image)) != MH_OK) {
        m_logger->error("failed to create load_image hook");
        return false;
    }

    if (MH_CreateHook(p_protect_image, &protect_image, reinterpret_cast<LPVOID*>(&m_protect_image)) != MH_OK) {
        m_logger->error("failed to create protect_image hook");
        return false;
    }

    if (MH_CreateHookApi(L"ntdll.dll", "NtQueryVirtualMemory", &nt_query_virtual_memory, reinterpret_cast<LPVOID*>(&m_nt_query_virtual_memory)) != MH_OK) {
        m_logger->error("failed to create nt_query_virtual_memory hook");
        return false;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        m_logger->error("failed to enable hooks");
        return false;
    }

    m_logger->success("ready\n");

    return true;
}

bool vacmon::hooks::uninstall() {

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    FreeConsole();
    return true;
}

bool __stdcall vacmon::hooks::load_image(
    steam::module_info* info,
    std::uint8_t flags
) {
    const auto manually_mapped{ (flags & 2) != 0 };

    const auto result{ hooks::get().m_load_image(info, flags) };

    if (info && info->mapped_module && manually_mapped) {

        auto& log{ *hooks::get().m_logger };

        log.info("load_image (return: {})", utils::format_address(_ReturnAddress()));
        log.write(" \x1b[93m-\x1b[90m crc32: 0x{:x}\n", info->crc32);
        log.write(" \x1b[93m-\x1b[90m image base: 0x{:x}\n", info->mapped_module->nt_headers->OptionalHeader.ImageBase);

        const auto folder{ utils::get_known_folder_path(FOLDERID_Desktop) / "vacmon" / "modules" };
        if (!std::filesystem::exists(folder) && !std::filesystem::create_directories(folder)) {

            hooks::get().m_logger->error("failed to create folder: \"{}\"", folder.string());
            log.write("\n");
            return result;
        }

        const auto file_name{ std::format("vac.0x{:X}.dll", info->crc32) };
        const auto full_path{ folder / file_name };

        if (std::filesystem::exists(full_path)) {
            log.write("\n");
            return result;
        }

        const auto image_base{ reinterpret_cast<void*>(info->mapped_module->nt_headers->OptionalHeader.ImageBase) };
        const auto image_size{ info->mapped_module->nt_headers->OptionalHeader.SizeOfImage };

        std::vector<std::uint8_t> image_data(image_size);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(image_base), image_size, image_data.data());

        log.write(" \x1b[93m-\x1b[90m section count: {}\n", info->mapped_module->nt_headers->FileHeader.NumberOfSections);
        log.write("\n");

        const auto dos_header{ reinterpret_cast<IMAGE_DOS_HEADER*>(image_data.data()) };
        const auto nt_headers{ reinterpret_cast<IMAGE_NT_HEADERS*>(image_data.data() + dos_header->e_lfanew) };

        for (std::uint16_t i{ 0 }; i < nt_headers->FileHeader.NumberOfSections; i++) {

            auto& section{ IMAGE_FIRST_SECTION(nt_headers)[i] };
            const auto alloc_section{ IMAGE_FIRST_SECTION(info->mapped_module->nt_headers) + i };
            section.PointerToRawData = alloc_section->VirtualAddress;
        }

        std::ofstream file(full_path, std::ios::out | std::ios::binary);
        if (file) {
            file.write(
                reinterpret_cast<const char*>(image_data.data()),
                image_size
            );
            hooks::get().m_logger->success("dumped module: {}\n", file_name);
        }
        else {
            hooks::get().m_logger->error("failed to open file: \"{}\"", full_path.string());
        }
    }

    return result;
}

int __cdecl vacmon::hooks::protect_image(
    steam::mapped_module_info* info
) {
    for (std::int16_t i{ 0 }; i < info->nt_headers->FileHeader.NumberOfSections; i++) {
        auto& section{ IMAGE_FIRST_SECTION(info->nt_headers)[i] };

        DWORD protection{ PAGE_READWRITE };
        if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protection = PAGE_EXECUTE_READWRITE;
        }

        VirtualProtect(reinterpret_cast<std::uint8_t*>(info->image_base) + section.VirtualAddress, section.Misc.VirtualSize, protection, &protection);
    }

    return info->nt_headers->FileHeader.NumberOfSections;
}

NTSTATUS NTAPI vacmon::hooks::nt_query_virtual_memory(
    HANDLE process_handle,
    PVOID base_address,
    MEMORY_INFORMATION_CLASS memory_information_class,
    PVOID memory_information,
    SIZE_T memory_information_length,
    PSIZE_T return_length
) {
    const auto result{ hooks::get().m_nt_query_virtual_memory(
        process_handle,
        base_address,
        memory_information_class,
        memory_information,
        memory_information_length,
        return_length
    ) };

    if (process_handle != GetCurrentProcess() &&
        memory_information_class == MEMORY_INFORMATION_CLASS::MemoryBasicInformation
    ) {
        auto& log{ *hooks::get().m_logger };

        log.info("nt_query_virtual_memory (return: 0x{:p})", utils::format_address(_ReturnAddress()));
        log.write(" \x1b[93m-\x1b[90m process_handle: 0x{:x}\n", reinterpret_cast<std::uintptr_t>(process_handle));
        log.write(" \x1b[93m-\x1b[90m base_address: 0x{:x}\n", reinterpret_cast<std::uintptr_t>(base_address));
        log.write(" \x1b[93m-\x1b[90m memory_information_class: 0x{:x}\n", static_cast<std::underlying_type_t<MEMORY_INFORMATION_CLASS>>(memory_information_class));
        log.write("\n");
    }

    return result;
}
