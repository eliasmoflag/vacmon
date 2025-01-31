#include "utils.hpp"

std::filesystem::path vacmon::utils::get_known_folder_path(const KNOWNFOLDERID& folder, KNOWN_FOLDER_FLAG flag) {

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

std::string vacmon::utils::format_address(const void* address) {

    HMODULE module_base;
    if (!GetModuleHandleExA(
        GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        reinterpret_cast<LPCSTR>(address),
        &module_base)) {

        return std::format("{:p}", address);
    }

    wchar_t module_path[MAX_PATH + 1]{ 0 };
    if (GetModuleFileNameW(
        module_base, module_path,
        std::size(module_path)) == 0) {

        return std::format("{:p}", address);
    }

    const auto file_name{ std::filesystem::path{ module_path }.filename().string() };

    const auto offset{
        reinterpret_cast<std::uintptr_t>(address) -
        reinterpret_cast<std::uintptr_t>(module_base)
    };

    return std::format("{}+0x{:x}", file_name, offset);
}
