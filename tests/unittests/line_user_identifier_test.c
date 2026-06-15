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

    lineAuthenticate(line, NULL);
    require(lineIsAuthenticated(line), "NULL handle did not authenticate line");
    require(line->last_user_identifier == 0, "NULL handle assigned a user identifier");

    lineAuthenticate(line, &empty);
    require(line->auth_cur == 2, "empty handle did not increment authentication count");
    require(line->last_user_identifier == 0, "empty handle assigned a user identifier");

    testLineDestroy(line);
}

static void testUserIdentifierMapping(void)
{
    user_handle_t first     = testUserHandle(0x11, 1);
    user_handle_t same_user = testUserHandle(0x11, 99);
    user_handle_t second    = testUserHandle(0x41, 1);

    line_t *line_a = testLineCreate();
    line_t *line_b = testLineCreate();
    line_t *line_c = testLineCreate();

    lineAuthenticate(line_a, &first);
    uint64_t first_id = line_a->last_user_identifier;
    require(first_id != 0, "valid user handle did not assign an identifier");

    lineAuthenticate(line_b, &same_user);
    require(line_b->last_user_identifier == first_id, "same SHA-256 did not reuse the same identifier");

    lineAuthenticate(line_c, &second);
    uint64_t second_id = line_c->last_user_identifier;
    require(second_id != 0, "second valid user handle did not assign an identifier");
    require(second_id != first_id, "different SHA-256 reused an existing identifier");

    lineAuthenticate(line_a, &second);
    require(line_a->last_user_identifier == second_id, "last_user_identifier was not updated on later auth");
    require(line_a->auth_cur == 2, "line authentication count did not increment on later auth");

    testLineDestroy(line_a);
    testLineDestroy(line_b);
    testLineDestroy(line_c);
}

int main(void)
{
    GSTATE = (ww_global_state_t) {0};
    atomicStoreRelaxed(&GSTATE.next_user_identifier, 1);
    GSTATE.line_user_identifier_registry = lineUserIdentifierRegistryCreate();

    testAnonymousAuthentication();
    testUserIdentifierMapping();

    lineUserIdentifierRegistryDestroy(GSTATE.line_user_identifier_registry);
    GSTATE = (ww_global_state_t) {0};

    return 0;
}
