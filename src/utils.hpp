#pragma once
#include <string>
#include <filesystem>
#include <ShlObj_core.h>

namespace vacmon::utils {
    std::filesystem::path get_known_folder_path(
        const KNOWNFOLDERID& folder,
        KNOWN_FOLDER_FLAG flag = KF_FLAG_DEFAULT
    );

    std::string format_address(const void* address);
}
