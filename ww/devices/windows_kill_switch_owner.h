#pragma once

#include <stdbool.h>
#include <stddef.h>

/* Configurations are built serially. An ordinal identifies a candidate across
 * files without retaining a pointer to a tunnel that may be rolled back. */
typedef struct ww_kill_switch_owner_s
{
    size_t eligible_count;
    size_t explicit_owner;
} ww_kill_switch_owner_t;

static inline bool wwKillSwitchConsiderTun(ww_kill_switch_owner_t *owner, bool eligible, bool marked, size_t *candidate)
{
    *candidate = 0;
    if (! eligible)
        return ! marked;
    if (marked && owner->explicit_owner != 0)
        return false;

    *candidate = ++owner->eligible_count;
    if (marked)
        owner->explicit_owner = *candidate;
    return true;
}

static inline size_t wwKillSwitchSelectedTun(const ww_kill_switch_owner_t *owner)
{
    if (owner->explicit_owner != 0)
        return owner->explicit_owner;
    return owner->eligible_count == 1 ? 1 : 0;
}
