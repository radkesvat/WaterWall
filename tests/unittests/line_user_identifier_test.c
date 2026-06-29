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
    if (line->last_authenticated_user_username != NULL)
    {
        memoryFree((void *) line->last_authenticated_user_username);
    }
    if (line->last_authenticated_user_password != NULL)
    {
        memoryFree((void *) line->last_authenticated_user_password);
    }
    memoryFree(line);
}

static void requireStringEquals(const char *actual, const char *expected, const char *message)
{
    require(actual != NULL, message);
    require(expected != NULL, message);
    require(stringLength(actual) == stringLength(expected), message);
    require(memoryEqual(actual, expected, stringLength(expected) + 1U), message);
}

static void requireUserHandleEquals(const user_handle_t *actual, const user_handle_t *expected, const char *message)
{
    require(actual != NULL, message);
    require(actual->generation == expected->generation, message);
    require(actual->user_id == expected->user_id, message);
}

static user_handle_t testUserHandle(uint64_t generation, uint64_t user_id)
{
    user_handle_t handle = userHandleEmpty();
    userHandleSet(&handle, generation, user_id);
    return handle;
}

static void testAnonymousUserHandlesRemainInvalid(void)
{
    line_t       *line  = testLineCreate();
    user_handle_t empty = userHandleEmpty();

    lineAddUser(line, NULL, NULL, NULL);
    require(lineIsAuthenticated(line), "NULL handle did not authenticate line");
    require(line->user_count == 1, "NULL handle did not increment line user count");
    require(! userHandleIsValid(&line->user_handles[0]), "NULL handle stored a valid user handle");
    require(line->user_handles[0].user_id == 0, "NULL handle assigned a user id");
    require(lineGetCurrentUser(line) == &line->user_handles[0], "current user did not point to first anonymous user");

    lineAddUser(line, &empty, NULL, NULL);
    require(line->user_count == 2, "empty handle did not increment line user count");
    require(! userHandleIsValid(&line->user_handles[1]), "empty handle stored a valid user handle");
    require(line->user_handles[1].user_id == 0, "empty handle assigned a user id");
    require(lineGetCurrentUser(line) == &line->user_handles[1], "current user did not point to latest anonymous user");

    testLineDestroy(line);
}

static void testUserHandleStoresPassedIdentifier(void)
{
    user_handle_t zero_id = testUserHandle(1, 0);
    user_handle_t first   = testUserHandle(99, 42);
    user_handle_t second  = testUserHandle(1, 77);

    require(! userHandleIsValid(&zero_id), "zero id user handle was valid");
    require(zero_id.user_id == 0, "zero id user handle did not clear id");
    require(first.user_id == 42, "first user handle did not keep the passed id");
    require(second.user_id == 77, "second user handle did not keep the passed id");
}

static void testLineUserRecording(void)
{
    user_handle_t first  = testUserHandle(1, 42);
    user_handle_t second = testUserHandle(2, 77);
    user_handle_t third  = testUserHandle(3, 99);
    user_handle_t empty  = userHandleEmpty();

    line_t *line = testLineCreate();
    require(lineGetCurrentUser(line) == NULL, "empty line returned a current user");

    lineAddUser(line, &first, NULL, NULL);
    require(line->user_count == 1, "line user count did not increment for first user");
    requireUserHandleEquals(&line->user_handles[0], &first, "line did not record first user handle");
    require(lineGetCurrentUser(line) == &line->user_handles[0], "current user did not point to first user");

    lineAddUser(line, &second, NULL, NULL);
    require(line->user_count == 2, "line user count did not increment for second user");
    requireUserHandleEquals(&line->user_handles[1], &second, "line did not record second user handle");
    require(lineGetCurrentUser(line) == &line->user_handles[1], "current user did not point to second user");

    lineAddUser(line, &third, NULL, NULL);
    require(line->user_count == 3, "line user count did not increment for third user");
    requireUserHandleEquals(&line->user_handles[2], &third, "line did not record third user handle");
    require(lineGetCurrentUser(line) == &line->user_handles[2], "current user did not point to third user");

    lineAddUser(line, &empty, NULL, NULL);
    require(line->user_count == kLineMaxUsers, "line did not allow exactly four user entries");
    require(! userHandleIsValid(&line->user_handles[3]), "line did not record anonymous user handle");
    require(line->user_handles[3].user_id == 0, "line did not record anonymous user marker");
    require(lineGetCurrentUser(line) == &line->user_handles[3], "current user did not point to anonymous user");

    testLineDestroy(line);
}

static void testLineUserCopy(void)
{
    user_handle_t first  = testUserHandle(7, 42);
    user_handle_t second = testUserHandle(11, 84);

    line_t *src  = testLineCreate();
    line_t *dest = testLineCreate();

    lineAddUser(src, &first, "first-user", "first-password");
    lineAddUser(src, &second, "second-user", "second-password");

    lineCopyUsers(dest, src);
    require(dest->user_count == src->user_count, "line user copy did not preserve user count");
    requireUserHandleEquals(&dest->user_handles[0], &src->user_handles[0], "line user copy lost first user");
    requireUserHandleEquals(&dest->user_handles[1], &src->user_handles[1], "line user copy lost second user");
    require(lineGetCurrentUser(dest) == &dest->user_handles[1], "line user copy did not preserve current user");
    requireStringEquals(lineGetAuthenticatedUsername(dest), "second-user", "line user copy lost username");
    requireStringEquals(lineGetAuthenticatedPassword(dest), "second-password", "line user copy lost password");
    require(lineGetAuthenticatedUsername(dest) != lineGetAuthenticatedUsername(src),
            "line user copy did not duplicate username");
    require(lineGetAuthenticatedPassword(dest) != lineGetAuthenticatedPassword(src),
            "line user copy did not duplicate password");

    testLineDestroy(dest);
    testLineDestroy(src);
}

static void testLineCredentialOnlyRecordingAndCopy(void)
{
    line_t *src  = testLineCreate();
    line_t *dest = testLineCreate();

    lineSetAuthenticatedCredentials(src, NULL, "uuid-password");
    require(src->user_count == 0, "credential-only line unexpectedly added a user marker");
    require(lineGetCurrentUser(src) == NULL, "credential-only line unexpectedly exposed a current user");
    require(lineGetAuthenticatedUsername(src) == NULL, "credential-only line unexpectedly stored a username");
    requireStringEquals(lineGetAuthenticatedPassword(src), "uuid-password", "credential-only line lost password");

    lineCopyUsers(dest, src);
    require(dest->user_count == 0, "credential-only copy unexpectedly added a user marker");
    require(lineGetCurrentUser(dest) == NULL, "credential-only copy unexpectedly exposed a current user");
    require(lineGetAuthenticatedUsername(dest) == NULL, "credential-only copy unexpectedly stored a username");
    requireStringEquals(lineGetAuthenticatedPassword(dest), "uuid-password", "credential-only copy lost password");
    require(lineGetAuthenticatedPassword(dest) != lineGetAuthenticatedPassword(src),
            "credential-only copy did not duplicate password");

    testLineDestroy(dest);
    testLineDestroy(src);
}

int main(void)
{
    testAnonymousUserHandlesRemainInvalid();
    testUserHandleStoresPassedIdentifier();
    testLineUserRecording();
    testLineUserCopy();
    testLineCredentialOnlyRecordingAndCopy();

    return 0;
}
