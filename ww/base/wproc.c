#include "wproc.h"
#include "wplatform.h"
#ifdef OS_WIN
#include <shellapi.h>

/**
 * @brief Checks whether the current process is running with administrative privileges.
 *
 * @return BOOL TRUE if running as admin, FALSE otherwise.
 */
bool isAdmin(void)
{
    BOOL   is_admin = FALSE;
    HANDLE h_token  = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token))
    {
        TOKEN_ELEVATION elevation;
        DWORD           dw_size;
        if (GetTokenInformation(h_token, TokenElevation, &elevation, sizeof(elevation), &dw_size))
        {
            is_admin = elevation.TokenIsElevated;
        }
    }

    if (h_token)
    {
        CloseHandle(h_token);
    }

    return is_admin;
}

/**
 * @brief Attempts to elevate the privileges of the current process.
 *
 * @param app_name The executable name of the application.
 * @param fail_msg The error message to display if elevation fails.
 * @return bool true on success, false otherwise.
 */
bool elevatePrivileges(const char *app_name, char *fail_msg)
{
    (void) app_name;
    (void) fail_msg;
    if (isAdmin())
    {
        return true;
    }
    return false;
    // char szPath[MAX_PATH];

    // // Retrieve the full path of the current executable
    // if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
    // {
    //     // Handle error
    //     printError("Failed to get executable path. Error: %lu\n", GetLastError());
    //     return false;
    // }

    // if (GetModuleFileName(NULL, szPath, MAX_PATH))
    // {
    //     SHELLEXECUTEINFO sei = {sizeof(sei)};
    //     sei.lpVerb           = L"runas"; // Request elevation
    //     sei.lpFile           = szPath;   // Path to the current executable
    //     sei.hwnd             = NULL;
    //     sei.nShow            = SW_NORMAL;

    //     if (! ShellExecuteEx(&sei))
    //     {
    //         DWORD dwError = GetLastError();
    //         if (dwError == ERROR_CANCELLED)
    //         {
    //             printError("User canceled the elevation prompt.\n");
    //         }
    //         else
    //         {
    //             printError("Failed to elevate privileges. Error: %lu\n", dwError);
    //         }
    //         return false;
    //     }
    //     else
    //     {
    //         // Successfully restarted with admin privileges
    //         ExitProcess(0); // Exit the current instance
    //     }
    // }

    return true;
}

#else

bool isAdmin(void)
{
    return true;
}

/**
 * @brief Stub for non-Windows platforms.
 *
 * @param app_name The executable name of the application.
 * @param fail_msg The error message, unused on non-Windows.
 * @return bool Always returns true.
 */
bool elevatePrivileges(const char *app_name, char *fail_msg)
{
    (void) app_name;
    (void) fail_msg;
    return true;
}

#endif
