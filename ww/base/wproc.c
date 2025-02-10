#include "wproc.h"
#include "wplatform.h"
#ifdef OS_WIN
#include <shellapi.h>

/**
 * @brief Checks whether the current process is running with administrative privileges.
 *
 * @return BOOL TRUE if running as admin, FALSE otherwise.
 */
BOOL isAdmin(void)
{
    BOOL is_admin = FALSE;
    HANDLE h_token = NULL;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &h_token))
    {
        TOKEN_ELEVATION elevation;
        DWORD dw_size;
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
bool windowsElevatePrivileges(const char *app_name, char *fail_msg)
{
    if (isAdmin())
    {
        return true;
    }

    SHELLEXECUTEINFO shell_exec_info = {
        .cbSize = sizeof(shell_exec_info),
        .fMask  = SEE_MASK_NOCLOSEPROCESS,
        .lpVerb = "runas",      // Request elevated privileges
        .lpFile = app_name,     // Application executable name
        .hwnd   = NULL,
        .nShow  = SW_NORMAL
    };

    if (!ShellExecuteEx(&shell_exec_info))
    {
        MessageBox(NULL, fail_msg, "Error", MB_OK | MB_ICONERROR);
        return false;
    }
    return true;
}

#else

/**
 * @brief Stub for non-Windows platforms.
 *
 * @param app_name The executable name of the application.
 * @param fail_msg The error message, unused on non-Windows.
 * @return bool Always returns true.
 */
bool windows_elevate_privileges(const char *app_name, char *fail_msg)
{
    (void) app_name;
    (void) fail_msg;
    return true;
}

#endif
