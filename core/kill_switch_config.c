#include "kill_switch_config.h"

#include "config_lexical.h"
#include <stdint.h>
#include <stdio.h>

bool waterwallParseKillSwitch(const cJSON *json, const char *input, size_t length, bool restricted, bool *enabled)
{
    *enabled            = false;
    const cJSON *option = cJSON_GetObjectItemCaseSensitive(json, "windows-kill-switch");
    if (option == NULL)
        return true;
    if (! cJSON_IsBool(option))
    {
        fputs("Windows kill switch: windows-kill-switch must be a boolean\n", stderr);
        return false;
    }

    /* The ordinary parser accepts trailing bytes and duplicate keys. Require
     * an unambiguous complete snapshot whenever it specifies an arming decision. */
    if (! restricted)
    {
        config_lexical_error_t error = {0};
        cJSON *checked = configLexicalParseBoundedWithError(input, length, CJSON_NESTING_LIMIT, SIZE_MAX, NULL, &error);
        if (checked == NULL)
        {
            fprintf(stderr, "Windows kill switch: invalid core JSON (%s) at byte %zu\n", error.category, error.offset);
            return false;
        }
        cJSON_Delete(checked);
    }
    *enabled = cJSON_IsTrue(option);
    return true;
}
