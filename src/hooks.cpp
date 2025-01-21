#include <Windows.h>
#include <ShlObj.h>
#include <MinHook.h>
#include <xscan.hpp>
#include <fstream>
#include <iostream>
#include <filesystem>
#include "hooks.hpp"

static std::filesystem::path get_known_folder_path(const KNOWNFOLDERID& folder, KNOWN_FOLDER_FLAG flag = KF_FLAG_DEFAULT);

static FILE* g_output{ nullptr };

bool vacmon::hooks::install() {

    AllocConsole();
    SetConsoleOutputCP(CP_UTF8);
    freopen_s(&g_output, "CONOUT$", "w", stdout);

    const auto console_output{ GetStdHandle(STD_OUTPUT_HANDLE) };
    if (DWORD console_mode{ 0 }; GetConsoleMode(console_output, &console_mode)) {
        SetConsoleMode(console_output, console_mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    }

    std::cout << "\x1b[93m";
    std::cout << "initializing..." << std::endl;

    const auto steamservice_dll{ reinterpret_cast<std::uint8_t*>(GetModuleHandleA("steamservice.dll")) };
    const auto p_load_image{ xscan::pattern{ "E8 ? ? ? ? 84 C0 75 16 8B 43 10" }
        .scan(xscan::pe_sections(steamservice_dll)).add(1).rip() };

    if (!p_load_image) {
        std::cout << "failed to find load_image." << std::endl;
        return false;
    }

    const auto p_protect_image{ xscan::pattern{ "E8 ? ? ? ? 8B 46 08 83 C4 04 8B 40 28" }
        .scan(xscan::pe_sections(steamservice_dll)).add(1).rip() };

    if (!p_protect_image) {
        std::cout << "failed to find protect_image." << std::endl;
        return false;
    }

    std::cout << "  load_image    : steamservice.dll+0x" << std::hex << (p_load_image - steamservice_dll) << std::endl;
    std::cout << "  protect_image : steamservice.dll+0x" << std::hex << (p_protect_image - steamservice_dll) << std::endl;

    if (MH_Initialize() != MH_OK) {
        std::cout << "failed to initialize minhook." << std::endl;
        return false;
    }

    if (MH_CreateHook(p_load_image, &load_image, reinterpret_cast<LPVOID*>(&m_load_image)) != MH_OK) {
        std::cout << "failed to create load_image hook." << std::endl;
        return false;
    }

    if (MH_CreateHook(p_protect_image, &protect_image, reinterpret_cast<LPVOID*>(&m_protect_image)) != MH_OK) {
        std::cout << "failed to create protect_image hook." << std::endl;
        return false;
    }

    if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK) {
        std::cout << "failed to enable hooks." << std::endl;
        return false;
    }

    std::cout << "\nready\n" << std::endl;
    return true;
}

bool vacmon::hooks::uninstall() {

    MH_DisableHook(MH_ALL_HOOKS);
    MH_Uninitialize();
    free(g_output);
    FreeConsole();
    return true;
}

bool __stdcall vacmon::hooks::load_image(module_info* info, std::uint8_t flags) {

    const auto manually_mapped{ (flags & 2) != 0 };

    const auto result{ m_load_image(info, flags) };

    if (info && info->mapped_module && manually_mapped) {

        std::cout << "ran module (0x"
            << std::hex << info->crc32 << ") at 0x"
            << std::hex << reinterpret_cast<std::uintptr_t>(info->mapped_module->image_base)
            << std::endl;

        const auto folder{ get_known_folder_path(FOLDERID_Desktop) / "vacmon" / "modules" };
        if (!std::filesystem::exists(folder) && !std::filesystem::create_directories(folder)) {

            std::cout << "failed to create folder: " << folder << std::endl;
            return result;
        }

        const auto file_name{ std::format("vac.0x{:X}.dll", info->crc32) };
        if (std::filesystem::exists(folder / file_name)) {
            return result;
        }

        const auto image_base{ info->mapped_module->image_base };
        const auto image_size{ info->mapped_module->nt_headers->OptionalHeader.SizeOfImage };

        std::vector<std::uint8_t> image_data(image_size);
        std::copy_n(reinterpret_cast<const std::uint8_t*>(image_base), image_data.size(), image_data.data());

        const auto dos_header{ reinterpret_cast<IMAGE_DOS_HEADER*>(image_data.data()) };
        const auto nt_headers{ reinterpret_cast<IMAGE_NT_HEADERS*>(image_data.data() + dos_header->e_lfanew) };

        nt_headers->OptionalHeader.ImageBase = reinterpret_cast<std::uintptr_t>(image_base);

        for (std::uint16_t i{ 0 }; i < nt_headers->FileHeader.NumberOfSections; i++) {

            auto& section{ IMAGE_FIRST_SECTION(nt_headers)[i] };

            section.PointerToRawData = section.VirtualAddress;
            section.SizeOfRawData = section.Misc.VirtualSize;
        }

        std::ofstream file(folder / file_name, std::ios::out | std::ios::binary);
        if (file) {
            file.write(
                reinterpret_cast<const char*>(image_data.data()),
                image_size
            );
            std::cout << "dumped " << file_name << std::endl;
        }
        else {
            std::cout << "failed to open file: " << folder / file_name << std::endl;
        }
    }

    return result;
}

int __cdecl vacmon::hooks::protect_image(mapped_module_info* info) {

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

std::filesystem::path get_known_folder_path(const KNOWNFOLDERID& folder, KNOWN_FOLDER_FLAG flag) {

    std::filesystem::path result;
    {
        wchar_t* path_buf{ nullptr };
        if (SUCCEEDED(::SHGetKnownFolderPath(folder, 0, 0, &path_buf))) {
            result = std::filesystem::path(path_buf);
        }

        ::CoTaskMemFree(path_buf);
    }
    return result;
}
