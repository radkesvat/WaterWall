#include "cJSON.h"
#include "config_lexical.h"
#include "launcher.h"
#include "startup_options.h"

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
        if (json != NULL)
        {
            cJSON_Delete(json);
        }
        waterwallStartupOptionsFreeCoreJson(content);
        return 1;
    }
    cJSON_Delete(json);

    return launcherExecute(content, input_len, options.core_json_input, argc, argv);
}

#ifndef WATERWALL_HAS_STARTUP_GUARD
int main(int argc, char **argv)
{
    return waterwallInnerMain(argc, argv);
}
#endif
