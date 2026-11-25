#include "cJSON.h"
#include "config_lexical.h"
#include "kill_switch_config.h"
#include "launcher.h"
#include "startup_options.h"
#ifdef _WIN32
#include "kill_switch_windows.h"
#include "lazy_loader.h"
#include "session_windows.h"
#ifdef WATERWALL_ENABLE_WINDOWS_KILL_SWITCH
#include "core_settings_preflight.h"
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int waterwallInnerMain(int argc, char **argv);

int waterwallInnerMain(int argc, char **argv)
{
    /* Reject reserved internal handoff arguments at the outer launcher boundary */
    for (int i = 1; i < argc; ++i)
    {
        if (argv[i] != NULL && strncmp(argv[i], "--ww-internal-", 14) == 0)
        {
            fprintf(stderr, "Invalid command-line argument \"%s\"\n", argv[i]);
            return 1;
        }
    }

    waterwall_startup_options_t          options = {0};
    waterwall_startup_arguments_result_e result  = waterwallStartupOptionsParse(argc, argv, &options);
    if (result != kWaterwallStartupArgumentsRun)
    {
        return result == kWaterwallStartupArgumentsExitSuccess ? 0 : 1;
    }

#ifdef _WIN32
    if (options.kill_switch_command != kWaterwallKillSwitchCommandNone)
        return launcherKillSwitchCommand(options.kill_switch_command);
    if (options.recover_file != NULL)
        return launcherSessionRecover(options.recover_file);
    if (! launcherSessionStart(&options))
    {
        char msg[128];
        lazyLoadString(transf_log_session_init_failed, sizeof(transf_log_session_init_failed), msg, sizeof(msg));
        fprintf(stderr, msg, GetLastError());
        SecureZeroMemory(msg, sizeof(msg));
        return 1;
    }
#endif

    size_t input_len = 0;
    char  *content   = waterwallStartupOptionsReadCoreJson(&options, &input_len);
    if (content == NULL)
    {
        return 1;
    }

    /* Basic JSON validation: syntax recognition and JSON object root */
    cJSON *json = NULL;
    if (options.restricted_config)
    {
        json = configLexicalParse(content, input_len, WW_HOST_JSON_DEPTH_LIMIT);
    }
    else
    {
        json = cJSON_Parse(content);
    }

    if (json == NULL || ! cJSON_IsObject(json))
    {
        if (options.restricted_config)
        {
            fprintf(stderr, "Restricted config: expected a JSON object\n");
        }
        else
        {
            waterwallStartupOptionsReportCoreJsonParseFailure(&options);
            if (json == NULL)
            {
                const char *error_ptr = cJSON_GetErrorPtr();
                if (error_ptr != NULL)
                {
                    fprintf(stderr, "JSON Error at byte %zu\n", (size_t) (error_ptr - content));
                }
            }
        }
// #ifdef OS_WINDOWS
//         launcherExtractApplicationOnJsonError();
// #endif
        if (json != NULL)
        {
            cJSON_Delete(json);
        }
        waterwallStartupOptionsFreeCoreJson(content);
        return 1;
    }
    bool valid =
        waterwallParseKillSwitch(json, content, input_len, options.restricted_config, &options.windows_kill_switch);
#if defined(_WIN32) && defined(WATERWALL_ENABLE_WINDOWS_KILL_SWITCH)
    if (valid && options.windows_kill_switch)
        valid = waterwallValidateProtectedCore(json);
#endif
    cJSON_Delete(json);
    if (! valid)
    {
        waterwallStartupOptionsFreeCoreJson(content);
        return 1;
    }
#if ! defined(_WIN32) || ! defined(WATERWALL_ENABLE_WINDOWS_KILL_SWITCH)
    if (options.windows_kill_switch)
    {
        fputs("Windows kill switch requires a packed Windows build with kill switch arming enabled.\n", stderr);
        waterwallStartupOptionsFreeCoreJson(content);
        return 1;
    }
#endif

    return launcherExecute(content, input_len, options.core_json_input, argc, argv, &options);
}

#ifndef WATERWALL_HAS_STARTUP_GUARD
int main(int argc, char **argv)
{
    return waterwallInnerMain(argc, argv);
}
#endif
