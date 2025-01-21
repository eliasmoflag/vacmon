#pragma once
#include <cstdint>
#include <cstddef>
#include <unordered_map>

namespace vacmon {

    class mapped_module_info;
    class module_info;

    using crc32_t = std::uint32_t;
    using run_func_t = int __stdcall(int, int, int, void *, module_info*);

    class hooks {
    public:
        static bool install();
        static bool uninstall();

    protected:
        static bool __stdcall load_image(module_info* info, std::uint8_t flags);
        static int __cdecl protect_image(mapped_module_info* info);

    protected:
        static inline decltype(&load_image) m_load_image;
        static inline decltype(&protect_image) m_protect_image;
    };

    class mapped_module_info {
    public:
        std::uint32_t dword0;
        void* image_base;
        IMAGE_NT_HEADERS* nt_headers;
        std::uint32_t dwordC;
        void* pvoid10;
    };

    class module_info {
    public:
        crc32_t crc32;
        std::uint32_t dword4;
        mapped_module_info* mapped_module;
        run_func_t* runfunc;
        std::int32_t status;
        std::uint32_t image_size;
        std::uint8_t* image_data;
    };
}
