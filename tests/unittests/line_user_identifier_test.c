#include "line.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "%s\n", message);
        exit(1);
    }
}

static line_t *testLineCreate(void)
{
    line_t *line = memoryAllocate(sizeof(*line));
    require(line != NULL, "failed to allocate test line");
    memoryZero(line, sizeof(*line));
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    memoryFree(line);
}

static void requireUserHandleEquals(const user_handle_t *actual, const user_handle_t *expected, const char *message)
{
    require(actual != NULL, message);
    require(memoryEqual(actual->sha256, expected->sha256, SHA256_DIGEST_SIZE), message);
    require(actual->generation == expected->generation, message);
    require(actual->local_global_identifier == expected->local_global_identifier, message);
}

static user_handle_t testUserHandle(uint8_t seed, uint64_t generation)
{
    uint8_t sha256[SHA256_DIGEST_SIZE] = {0};

    for (size_t i = 0; i < sizeof(sha256); ++i)
    {
        sha256[i] = (uint8_t) (seed + (uint8_t) (i * 13U));
    }

    user_handle_t handle = userHandleEmpty();
    userHandleSet(&handle, sha256, generation);
    return handle;
}

static void testAnonymousAuthentication(void)
{
    line_t        *line  = testLineCreate();
    user_handle_t empty = userHandleEmpty();

    lineAddUser(line, NULL);
    require(lineIsAuthenticated(line), "NULL handle did not authenticate line");
    require(line->user_count == 1, "NULL handle did not increment line user count");
    require(! userHandleIsValid(&line->user_handles[0]), "NULL handle stored a valid user handle");
    require(line->user_handles[0].local_global_identifier == 0, "NULL handle assigned a user identifier");
    require(lineGetCurrentUser(line) == &line->user_handles[0], "current user did not point to first anonymous user");

    lineAddUser(line, &empty);
    require(line->user_count == 2, "empty handle did not increment line user count");
    require(! userHandleIsValid(&line->user_handles[1]), "empty handle stored a valid user handle");
    require(line->user_handles[1].local_global_identifier == 0, "empty handle assigned a user identifier");
    require(lineGetCurrentUser(line) == &line->user_handles[1], "current user did not point to latest anonymous user");

    testLineDestroy(line);
}

static void testUserHandleIdentifierMapping(void)
{
    user_handle_t first     = testUserHandle(0x11, 1);
    user_handle_t same_user = testUserHandle(0x11, 99);
    user_handle_t second    = testUserHandle(0x41, 1);

    uint64_t first_id = first.local_global_identifier;
    require(first_id != 0, "valid user handle did not assign an identifier");
    require(same_user.local_global_identifier == first_id, "same SHA-256 did not reuse the same identifier");

    uint64_t second_id = second.local_global_identifier;
    require(second_id != 0, "second valid user handle did not assign an identifier");
    require(second_id != first_id, "different SHA-256 reused an existing identifier");
}

static void testLineUserRecording(void)
{
    user_handle_t first     = testUserHandle(0x11, 1);
    user_handle_t same_user = testUserHandle(0x11, 99);
    user_handle_t second    = testUserHandle(0x41, 1);
    user_handle_t empty     = userHandleEmpty();

    line_t *line = testLineCreate();
    require(lineGetCurrentUser(line) == NULL, "empty line returned a current user");

    lineAddUser(line, &first);
    require(line->user_count == 1, "line user count did not increment for first user");
    requireUserHandleEquals(&line->user_handles[0], &first, "line did not record first user handle");
    require(lineGetCurrentUser(line) == &line->user_handles[0], "current user did not point to first user");

    lineAddUser(line, &same_user);
    require(line->user_count == 2, "line user count did not increment for same user");
    requireUserHandleEquals(&line->user_handles[1], &same_user, "line did not record reused user handle");
    require(lineGetCurrentUser(line) == &line->user_handles[1], "current user did not point to reused user");

    lineAddUser(line, &second);
    require(line->user_count == 3, "line user count did not increment for second user");
    requireUserHandleEquals(&line->user_handles[2], &second, "line did not record second user handle");
    require(lineGetCurrentUser(line) == &line->user_handles[2], "current user did not point to second user");

    lineAddUser(line, &empty);
    require(line->user_count == kLineMaxUsers, "line did not allow exactly four user entries");
    require(! userHandleIsValid(&line->user_handles[3]), "line did not record anonymous user handle");
    require(line->user_handles[3].local_global_identifier == 0, "line did not record anonymous user marker");
    require(lineGetCurrentUser(line) == &line->user_handles[3], "current user did not point to anonymous user");

    testLineDestroy(line);
}

static void testLineUserCopy(void)
{
    user_handle_t first  = testUserHandle(0x21, 7);
    user_handle_t second = testUserHandle(0x71, 11);

    line_t *src  = testLineCreate();
    line_t *dest = testLineCreate();

    lineAddUser(src, &first);
    lineAddUser(src, &second);

    lineCopyUsers(dest, src);
    require(dest->user_count == src->user_count, "line user copy did not preserve user count");
    requireUserHandleEquals(&dest->user_handles[0], &src->user_handles[0], "line user copy lost first user");
    requireUserHandleEquals(&dest->user_handles[1], &src->user_handles[1], "line user copy lost second user");
    require(lineGetCurrentUser(dest) == &dest->user_handles[1], "line user copy did not preserve current user");

    testLineDestroy(dest);
    testLineDestroy(src);
}

int main(void)
{
    GSTATE = (ww_global_state_t) {0};
    atomicStoreRelaxed(&GSTATE.next_user_handle_identifier, 1);
    GSTATE.user_handle_identifier_registry = userHandleIdentifierRegistryCreate();

    testAnonymousAuthentication();
    testUserHandleIdentifierMapping();
    testLineUserRecording();
    testLineUserCopy();

    userHandleIdentifierRegistryDestroy(GSTATE.user_handle_identifier_registry);
    GSTATE = (ww_global_state_t) {0};

    return 0;
}
