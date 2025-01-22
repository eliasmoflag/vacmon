#pragma once
#include <Windows.h>
#include <cstdint>

namespace vacmon::steam {
    using crc32_t = std::uint32_t;

    using run_func_t = int __stdcall(int, int, int, void*, class module_info*);

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
