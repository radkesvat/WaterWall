#include "user_internal.h"
#include "users_internal.h"

user_public_result_t usersTryCount(const users_t *users, uint64_t deadline_ms, size_t *count_out)
{
    assert(users != NULL && count_out != NULL);
    *count_out = 0;
    if (userDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &users->lock))
        return kUserPublicBusy;
    size_t count = users->count;
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    if (userDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    *count_out = count;
    return kUserPublicOk;
}

user_public_result_t usersCopyPublicDetailByIdentifier(const users_t *users, uint64_t id, size_t max_string_bytes,
                                                       uint64_t deadline_ms, user_public_detail_t *out)
{
    assert(users != NULL && id != 0 && out != NULL);
    memoryZero(out, sizeof(*out));
    if (userDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &users->lock))
        return kUserPublicBusy;
    user_t              *user = usersIDTableLookupLocked(users, id);
    user_public_result_t result =
        user == NULL ? kUserPublicNotFound : userCopyPublicDetail(user, max_string_bytes, deadline_ms, out);
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    if (userDeadlineExpired(deadline_ms))
    {
        userPublicDetailDestroy(out);
        result = kUserPublicTimeout;
    }
    return result;
}

user_public_result_t usersCopyPublicPage(const users_t *users, size_t position, size_t limit, uint64_t deadline_ms,
                                         user_public_summary_t *entries_out, size_t *count_out, size_t *total_out)
{
    assert(users != NULL && limit > 0 && limit <= USER_PUBLIC_PAGE_MAX && entries_out != NULL && count_out != NULL &&
           total_out != NULL);
    *count_out = 0;
    *total_out = 0;
    memoryZero(entries_out, limit * sizeof(*entries_out));
    if (userDeadlineExpired(deadline_ms))
        return kUserPublicTimeout;
    if (! rwlockTryReadLock((wrwlock_t *) &users->lock))
        return kUserPublicBusy;
    user_public_result_t result = kUserPublicOutOfRange;
    size_t               count  = 0;
    if (position > users->count)
        goto done;
    count = min(limit, users->count - position);
    for (size_t i = 0; i < count; ++i)
    {
        result = userCopyPublicSummary(usersGetAtLocked(users, position + i), deadline_ms, &entries_out[i]);
        if (result != kUserPublicOk)
            goto done;
    }
    result = userDeadlineExpired(deadline_ms) ? kUserPublicTimeout : kUserPublicOk;
    if (result == kUserPublicOk)
    {
        *count_out = count;
        *total_out = users->count;
    }
done:
    rwlockReadUnlock((wrwlock_t *) &users->lock);
    if (result != kUserPublicOk)
        memoryZero(entries_out, limit * sizeof(*entries_out));
    return result;
}

user_public_result_t usersCopyFullUserJsonAt(const users_t *users, size_t position, size_t max_encoded, cJSON **out,
                                             size_t *encoded_size)
{
    assert(users != NULL && out != NULL && encoded_size != NULL);
    *out          = NULL;
    *encoded_size = 0;
    rwlockReadLock(&((users_t *) users)->lock);
    user_public_result_t result =
        position >= users->count
            ? kUserPublicOutOfRange
            : userCopyFullJsonBounded(usersGetAtLocked(users, position), max_encoded, out, encoded_size);
    rwlockReadUnlock(&((users_t *) users)->lock);
    return result;
}
