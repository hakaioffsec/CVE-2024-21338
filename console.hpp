#ifndef CONSOLE_LOGGER_HPP
#define CONSOLE_LOGGER_HPP

#include <Windows.h>

#include <iostream>
#include <shared_mutex>

enum class msg_type_t : std::uint32_t
{
	LNONE = 0,
	LDEBUG = 9,		/* blue */
	LSUCCESS = 10,	/* green */
	LERROR = 12,	/* red */
	LWARN = 14		/* yellow */
};

inline std::ostream& operator<< (std::ostream& os, const msg_type_t type)
{
	switch (type)
	{
	case msg_type_t::LDEBUG:	return os << ".";
	case msg_type_t::LSUCCESS:	return os << "+";
	case msg_type_t::LERROR:	return os << "!";
	case msg_type_t::LWARN:		return os << "*";
	default: return os << "";
	}
}

class logger
{
private:
	std::shared_timed_mutex mutex;

public:
	logger(const std::wstring_view title_name = {})
	{
		AllocConsole();
		AttachConsole(GetCurrentProcessId());

		if (!title_name.empty())
			SetConsoleTitle(title_name.data());

		FILE* conin, * conout;

		freopen_s(&conin, "conin$", "r", stdin);
		freopen_s(&conout, "conout$", "w", stdout);
		freopen_s(&conout, "conout$", "w", stderr);
	}

	~logger()
	{
		const auto handle = FindWindow(L"ConsoleWindowClass", nullptr);
		ShowWindow(handle, SW_HIDE);
		FreeConsole();
	}

	template< typename ... arg >
	void print(const msg_type_t type, const std::string_view& func, const std::string& format, arg ... a)
	{
		static auto* h_console = GetStdHandle(STD_OUTPUT_HANDLE);
		std::unique_lock<decltype(mutex)> lock(mutex);

		const size_t size = (size_t)(1) + std::snprintf(nullptr, 0, format.c_str(), a ...);
		const std::unique_ptr<char[]> buf(new char[size]);
		std::snprintf(buf.get(), size, format.c_str(), a ...);
		const auto formated = std::string(buf.get(), buf.get() + size - 1);

		if (type != msg_type_t::LNONE)
		{
			SetConsoleTextAttribute(h_console, (WORD)(type));
			std::cout << "[";
			std::cout << type;
			std::cout << "] ";

			SetConsoleTextAttribute(h_console, 15 /* white */);
			std::cout << "[ ";

			SetConsoleTextAttribute(h_console, (WORD)(type));
			std::cout << func;

			SetConsoleTextAttribute(h_console, 15 /* white */);
			std::cout << " ] ";
		}

		if (type == msg_type_t::LDEBUG)
			SetConsoleTextAttribute(h_console, 8 /* gray */);
		else
			SetConsoleTextAttribute(h_console, 15 /* white */);

		std::cout << formated << "\n";
	}
};

//#ifdef _DEBUG
inline auto g_logger = logger(L"");
#define log_debug(...)	g_logger.print( msg_type_t::LDEBUG, __FUNCTION__, __VA_ARGS__ )
#define log_ok(...)		g_logger.print( msg_type_t::LSUCCESS, __FUNCTION__, __VA_ARGS__ )
#define log_err(...)	g_logger.print( msg_type_t::LERROR, __FUNCTION__, __VA_ARGS__ )
#define log_warn(...)	g_logger.print( msg_type_t::LWARN, __FUNCTION__, __VA_ARGS__ )
#define log_raw(...)	g_logger.print( msg_type_t::LNONE, __FUNCTION__, __VA_ARGS__ )
//#else
//#define log_debug(...)
//#define log_ok(...)
//#define log_err(...)
//#define log_warn(...)
//#define log_raw(...)
//#endif

#endif // guard