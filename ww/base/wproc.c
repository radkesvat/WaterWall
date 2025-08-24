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
            is_admin = (BOOL)elevation.TokenIsElevated;
        }
    }

    if (h_token)
    {
        CloseHandle(h_token);
    }

    return is_admin;
}


bool elevatePrivileges(const char *app_name, char *fail_msg)
{
    discard app_name;
    discard fail_msg;
    return false; // for now

    if (isAdmin())
    {
        return true;
    }
    char szPath[MAX_PATH];

    // Retrieve the full path of the current executable
    if (GetModuleFileName(NULL, szPath, MAX_PATH) == 0)
    {
        // Handle error
        printError("Failed to get executable path. Error: %lu\n", GetLastError());
        return false;
    }

    if (GetModuleFileName(NULL, szPath, MAX_PATH))
    {
        SHELLEXECUTEINFO sei = {
            .cbSize = sizeof(sei),
            .fMask = 0,
            .hwnd = NULL,
            .lpVerb = "runas", // Request elevation
            .lpFile = szPath,  // Path to the current executable
            .nShow = SW_NORMAL
        };

        if (! ShellExecuteEx(&sei))
        {
            DWORD dwError = GetLastError();
            if (dwError == ERROR_CANCELLED)
            {
                printError("User canceled the elevation prompt.\n");
            }
            else
            {
                printError("Failed to elevate privileges. Error: %lu\n", dwError);
            }
            return false;
        }
        else
        {
            // Successfully restarted with admin privileges
            ExitProcess(0); // Exit the current instance
        }
    }

    return true;
}

#else

bool isAdmin(void)
{
    return true;
}


bool elevatePrivileges(const char *app_name, char *fail_msg)
{
    discard app_name;
    discard fail_msg;
    return true;
}

#endif
