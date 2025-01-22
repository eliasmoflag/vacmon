#pragma once
#include <cstdint>
#include <memory>

namespace vacmon {
    class logger;

    namespace steam {
        class mapped_module_info;
        class module_info;
    }

    class hooks {
    public:
        static hooks& get();

        bool install();
        bool uninstall();

    protected:
        static bool __stdcall load_image(steam::module_info* info, std::uint8_t flags);
        static int __cdecl protect_image(steam::mapped_module_info* info);

    protected:
        decltype(&load_image) m_load_image;
        decltype(&protect_image) m_protect_image;

        std::unique_ptr<logger> m_logger;
    };
}
