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
