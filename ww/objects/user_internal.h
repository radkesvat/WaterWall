#pragma once
#include "objects/user.h"

/* Configuration ownership is held while admitting and constructing an owned row. */
user_public_result_t userCopyFullJsonBounded(User *user, size_t limit, cJSON **out, size_t *encoded_size);
/* Fresh initialized destination locks; transfers owned values without native-lock copying. */
bool userMoveOwnedValue(User *dest, User *source);

/* A normalized CIDR prepared before checked JSON construction, with owned text. */
typedef struct user_allowed_ip_preparation_s
{
    char                    *text;
    user_parsed_allowed_ip_t value;
} user_allowed_ip_preparation_t;
bool userPrepareJsonAllowedIps(const cJSON *json, user_allowed_ip_preparation_t *prepared);
bool userCreateFromJsonPreparedAllowedIps(User *user, const cJSON *json, user_allowed_ip_preparation_t *prepared);
user_json_result_t userCreateFromJsonPreparedAllowedIpsResult(User *user, const cJSON *json,
                                                              user_allowed_ip_preparation_t *prepared);
/* Caller owns configuration. Replacement metadata is assembled before locks. */
user_public_result_t userMeasureExportFields(const user_export_strings_t        *strings,
                                             const user_export_string_measure_t *password, size_t limit,
                                             size_t *encoded_size);

/* A zero deadline is unlimited; all object deadlines use monotonic time. */
static inline bool userDeadlineExpired(uint64_t deadline_ms)
{
    return deadline_ms != 0 && getHRTimeUs() / 1000U >= deadline_ms;
}
