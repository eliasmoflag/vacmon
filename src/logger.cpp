#include <Windows.h>
#include "logger.hpp"

vacmon::logger::logger(const std::string& console_title) {
	if (AllocConsole()) {
		SetConsoleOutputCP(CP_UTF8);
		SetConsoleTitleA(console_title.c_str());

		if (const auto console_window{ GetConsoleWindow() }; console_window) {
			SetLayeredWindowAttributes(console_window, RGB(255, 255, 255), 0xF0, LWA_ALPHA);
		}

		if ((m_output_handle = GetStdHandle(STD_OUTPUT_HANDLE)) != INVALID_HANDLE_VALUE) {
			if (DWORD mode{ 0 }; GetConsoleMode(m_output_handle, &mode)) {
				SetConsoleMode(m_output_handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
			}
		}
		else {
			m_output_handle = NULL;
		}
	}
}

vacmon::logger::~logger() {
	if (m_output_handle) {
		FreeConsole();
	}
}

void vacmon::logger::write(const std::string_view buffer) const {

	if (m_output_handle) {
		WriteConsoleA(m_output_handle, buffer.data(), buffer.size(), nullptr, nullptr);
	}
}

void vacmon::logger::write(const level_enum level, const std::string_view buffer) const {

	switch (level) {
	case level_enum::info:
		return write(std::format("\x1b[97m[\x1b[93m*\x1b[37m] \x1b[90m{}\n", buffer));
	case level_enum::warn:
		return write(std::format("\x1b[97m[\x1b[93m!\x1b[97m] \x1b[90m{}\n", buffer));
	case level_enum::error:
		return write(std::format("\x1b[97m[\x1b[91m-\x1b[97m] \x1b[90m{}\n", buffer));
	case level_enum::success:
		return write(std::format("\x1b[97m[\x1b[92m+\x1b[97m] \x1b[90m{}\n", buffer));
	}
}
