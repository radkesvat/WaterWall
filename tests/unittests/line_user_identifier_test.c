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
    line_t *line = memoryAllocateZero(sizeof(*line));
    require(line != NULL, "failed to allocate test line");
    line->alive = true;
    return line;
}

static void testLineDestroy(line_t *line)
{
    lineClearUsers(line);
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

static const user_handle_t *requireHandleEntry(line_t *line, uint8_t index, const char *message)
{
    require(index < line->user_count, message);
    require(line->user_auths[index].has_handle, message);
    return &line->user_auths[index].handle;
}

static const line_user_credentials_t *requireCredentialsEntry(line_t *line, uint8_t index, const char *message)
{
    require(index < line->user_count, message);
    require(line->user_auths[index].has_credentials, message);
    return &line->user_auths[index].credentials;
}

static user_handle_t testUserHandle(uint64_t generation, uint64_t user_id)
{
    user_handle_t handle = userHandleEmpty();
    userHandleSet(&handle, generation, user_id);
    return handle;
}

static void testAnonymousUserHandlesRemainInvalid(void)
{
    line_t              *line   = testLineCreate();
    user_handle_t        empty  = userHandleEmpty();
    const user_handle_t *stored = NULL;

    lineAddUser(line, NULL, NULL, NULL);
    require(lineIsAuthenticated(line), "NULL handle did not authenticate line");
    require(line->user_count == 1, "NULL handle did not increment line user count");
    stored = requireHandleEntry(line, 0, "NULL handle did not store a handle marker");
    require(! userHandleIsValid(stored), "NULL handle stored a valid user handle");
    require(stored->user_id == 0, "NULL handle assigned a user id");
    require(lineGetCurrentUser(line) == stored, "current user did not point to first anonymous user");

    lineAddUser(line, &empty, NULL, NULL);
    require(line->user_count == 2, "empty handle did not increment line user count");
    stored = requireHandleEntry(line, 1, "empty handle did not store a handle marker");
    require(! userHandleIsValid(stored), "empty handle stored a valid user handle");
    require(stored->user_id == 0, "empty handle assigned a user id");
    require(lineGetCurrentUser(line) == stored, "current user did not point to latest anonymous user");

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
    user_handle_t        first     = testUserHandle(1, 42);
    user_handle_t        second    = testUserHandle(2, 77);
    user_handle_t        third     = testUserHandle(3, 99);
    user_handle_t        empty     = userHandleEmpty();
    line_t              *line      = testLineCreate();
    const user_handle_t *anonymous = NULL;

    require(lineGetCurrentUser(line) == NULL, "empty line returned a current user");

    lineAddUser(line, &first, NULL, NULL);
    require(line->user_count == 1, "line user count did not increment for first user");
    requireUserHandleEquals(requireHandleEntry(line, 0, "first user was not a handle marker"), &first,
                            "line did not record first user handle");
    require(lineGetCurrentUser(line) == requireHandleEntry(line, 0, "first user marker disappeared"),
            "current user did not point to first user");

    lineAddUser(line, &second, NULL, NULL);
    require(line->user_count == 2, "line user count did not increment for second user");
    requireUserHandleEquals(requireHandleEntry(line, 1, "second user was not a handle marker"), &second,
                            "line did not record second user handle");
    require(lineGetCurrentUser(line) == requireHandleEntry(line, 1, "second user marker disappeared"),
            "current user did not point to second user");

    lineAddUser(line, &third, NULL, NULL);
    require(line->user_count == 3, "line user count did not increment for third user");
    requireUserHandleEquals(requireHandleEntry(line, 2, "third user was not a handle marker"), &third,
                            "line did not record third user handle");
    require(lineGetCurrentUser(line) == requireHandleEntry(line, 2, "third user marker disappeared"),
            "current user did not point to third user");

    lineAddUser(line, &empty, NULL, NULL);
    require(line->user_count == kLineMaxUsers, "line did not allow exactly four user entries");
    anonymous = requireHandleEntry(line, 3, "anonymous user was not a handle marker");
    require(! userHandleIsValid(anonymous), "line did not record anonymous user handle");
    require(anonymous->user_id == 0, "line did not record anonymous user marker");
    require(lineGetCurrentUser(line) == anonymous, "current user did not point to anonymous user");

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
    require(dest->user_count == 2, "handle-plus-credential users were not stored as two auth layers");
    requireStringEquals(requireCredentialsEntry(dest, 0, "line user copy lost first credentials")->username,
                        "first-user",
                        "line user copy lost first username");
    requireStringEquals(requireCredentialsEntry(dest, 0, "line user copy lost first credentials")->password,
                        "first-password",
                        "line user copy lost first password");
    requireUserHandleEquals(requireHandleEntry(dest, 0, "line user copy lost first handle"), &first,
                            "line user copy lost first user");
    requireStringEquals(requireCredentialsEntry(dest, 1, "line user copy lost second credentials")->username,
                        "second-user",
                        "line user copy lost second username");
    requireStringEquals(requireCredentialsEntry(dest, 1, "line user copy lost second credentials")->password,
                        "second-password",
                        "line user copy lost second password");
    requireUserHandleEquals(requireHandleEntry(dest, 1, "line user copy lost second handle"), &second,
                            "line user copy lost second user");
    require(lineGetCurrentUser(dest) == requireHandleEntry(dest, 1, "line user copy lost latest handle"),
            "line user copy did not preserve current user");
    requireStringEquals(lineGetAuthenticatedUsername(dest), "second-user", "line user copy lost username");
    requireStringEquals(lineGetAuthenticatedPassword(dest), "second-password", "line user copy lost password");
    require(lineGetAuthenticatedUsername(dest) != lineGetAuthenticatedUsername(src),
            "line user copy did not duplicate username");
    require(lineGetAuthenticatedPassword(dest) != lineGetAuthenticatedPassword(src),
            "line user copy did not duplicate password");
    require(lineHasAuthenticatedCredentials(dest, "first-user", "first-password"),
            "line user copy did not preserve first credential pair");
    require(lineHasAuthenticatedCredentials(dest, "second-user", "second-password"),
            "line user copy did not preserve second credential pair");
    require(! lineHasAuthenticatedCredentials(dest, "first-user", "second-password"),
            "line credential pair matching crossed auth layers");

    testLineDestroy(dest);
    testLineDestroy(src);
}

static void testLineCredentialOnlyRecordingAndCopy(void)
{
    line_t *src  = testLineCreate();
    line_t *dest = testLineCreate();

    lineAddAuthenticatedCredentials(src, NULL, "uuid-password");
    require(src->user_count == 1, "credential-only line did not add a credential marker");
    require(lineIsAuthenticated(src), "credential-only line was not authenticated");
    require(lineGetCurrentUser(src) == NULL, "credential-only line unexpectedly exposed a current user");
    require(lineGetAuthenticatedUsername(src) == NULL, "credential-only line unexpectedly stored a username");
    requireStringEquals(lineGetAuthenticatedPassword(src), "uuid-password", "credential-only line lost password");
    require(lineHasAuthenticatedPassword(src, "uuid-password"), "credential-only line did not match password");

    lineCopyUsers(dest, src);
    require(dest->user_count == 1, "credential-only copy did not preserve credential marker");
    require(lineGetCurrentUser(dest) == NULL, "credential-only copy unexpectedly exposed a current user");
    require(lineGetAuthenticatedUsername(dest) == NULL, "credential-only copy unexpectedly stored a username");
    requireStringEquals(lineGetAuthenticatedPassword(dest), "uuid-password", "credential-only copy lost password");
    require(lineGetAuthenticatedPassword(dest) != lineGetAuthenticatedPassword(src),
            "credential-only copy did not duplicate password");

    testLineDestroy(dest);
    testLineDestroy(src);
}

static void testStackedRawCredentialsRemainAddressable(void)
{
    line_t *line = testLineCreate();

    lineAddAuthenticatedCredentials(line, "vless-user", "vless-password");
    lineAddAuthenticatedCredentials(line, "trojan-user", "trojan-password");

    require(line->user_count == 2, "stacked raw credentials did not preserve both entries");
    requireStringEquals(lineGetAuthenticatedUsername(line), "trojan-user", "latest credential username was wrong");
    requireStringEquals(lineGetAuthenticatedPassword(line), "trojan-password", "latest credential password was wrong");
    require(lineHasAuthenticatedCredentials(line, "vless-user", "vless-password"),
            "first credential pair was not matchable");
    require(lineHasAuthenticatedCredentials(line, "trojan-user", "trojan-password"),
            "second credential pair was not matchable");
    require(lineHasAuthenticatedUsername(line, "vless-user"), "first username was not matchable");
    require(lineHasAuthenticatedPassword(line, "trojan-password"), "second password was not matchable");
    require(! lineHasAuthenticatedCredentials(line, "vless-user", "trojan-password"),
            "credential pair matching crossed stacked raw auth entries");

    testLineDestroy(line);
}

int main(void)
{
    testAnonymousUserHandlesRemainInvalid();
    testUserHandleStoresPassedIdentifier();
    testLineUserRecording();
    testLineUserCopy();
    testLineCredentialOnlyRecordingAndCopy();
    testStackedRawCredentialsRemainAddressable();

    return 0;
}
