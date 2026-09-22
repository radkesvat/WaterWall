#include "structure.h"

bool bgp4serverLoadSettings(bgp4server_tstate_t *ts, const cJSON *settings)
{
    char *password = NULL;
    getStringFromJsonObjectOrDefault(&password, settings, "password", "passwd");
    ts->password_hash = calcHashBytes(password, stringLength(password));
    memoryFree(password);

    ts->as_number = (uint16_t) fastRand();
    ts->router_id = fastRand() * 3U;
    return true;
}
