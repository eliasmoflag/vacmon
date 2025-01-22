#pragma once
#include <string>
#include <format>
#include <type_traits>

namespace vacmon {
    class logger {
    public:
        logger(const std::string& console_title);
        ~logger();

        enum class level_enum {
            info,
            warn,
            error,
            success,
            COUNT
        };

        void write(const std::string_view buffer) const;
        void write(const level_enum level, const std::string_view buffer) const;

        template<typename... arguments>
        inline void write(const std::string_view format, arguments&&... args) const {
            write(std::vformat(format, std::make_format_args(args...)));
        }

        template<typename... arguments>
        inline void write(const level_enum level, const std::string_view format, arguments&&... args) const {
            write(level, std::vformat(format, std::make_format_args(args...)));
        }

        template<typename... arguments>
        inline void info(const std::string_view format, arguments&&... args) const {
            write(level_enum::info, std::vformat(format, std::make_format_args(args...)));
        }

        template<typename... arguments>
        inline void warn(const std::string_view format, arguments&&... args) const {
            write(level_enum::warn, std::vformat(format, std::make_format_args(args...)));
        }

        template<typename... arguments>
        inline void error(const std::string_view format, arguments&&... args) const {
            write(level_enum::error, std::vformat(format, std::make_format_args(args...)));
        }

        template<typename... arguments>
        inline void success(const std::string_view format, arguments&&... args) const {
            write(level_enum::success, std::vformat(format, std::make_format_args(args...)));
        }

    protected:
        HANDLE m_output_handle{ 0 };
    };
}
