/* CTest: waterwall.authentication_portability_unit
 * Real portable protocol, CIDR/JSON parsing and private-file operations. The native runner
 * supplies an isolated working directory; this fixture creates a private child.
 * No sockets, worker loops, permission assumptions under root, or fault wrappers. */
#include "AuthenticationServer/api.h"
#include "loggers/network_logger.h"
#include "node_builder/config_lexical.h"
#include "private_file.h"
#include "test_assert.h"

#ifdef OS_WIN
#include <io.h>
#include <sddl.h>
#define fixtureClose  _close
#define fixtureDup    _dup
#define fixtureDup2   _dup2
#define fixtureFileno _fileno
#else
#define fixtureClose  close
#define fixtureDup    dup
#define fixtureDup2   dup2
#define fixtureFileno fileno
#endif

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static const char directory[] = "auth-portability-private";
static const char primary[]   = "auth-portability-private/users.json";

static void createPrivateDirectory(void)
{
#ifdef OS_WIN
    HANDLE token = NULL;
    DWORD  size  = 0;
    require(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "private-directory token open failed");
    GetTokenInformation(token, TokenUser, NULL, 0, &size);
    require(size > 0, "private-directory token size failed");
    void *user = memoryAllocate(size);
    char *sid  = NULL;
    require(GetTokenInformation(token, TokenUser, user, size, &size) &&
                ConvertSidToStringSidA(((TOKEN_USER *) user)->User.Sid, &sid),
            "private-directory identity lookup failed");
    char                 sddl[512];
    int                  count    = snprintf(sddl, sizeof(sddl), "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;%s)", sid);
    PSECURITY_DESCRIPTOR security = NULL;
    require(count > 0 && (size_t) count < sizeof(sddl) &&
                ConvertStringSecurityDescriptorToSecurityDescriptorA(sddl, SDDL_REVISION_1, &security, NULL),
            "private-directory security construction failed");
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), security, FALSE};
    bool                created    = CreateDirectoryA(directory, &attributes) != 0;
    LocalFree(security);
    LocalFree(sid);
    memoryFree(user);
    require(CloseHandle(token) && created, "private-directory creation failed");
#else
    require(mkdir(directory, 0700) == 0, "private-directory creation failed");
    struct stat info;
    require(stat(directory, &info) == 0 && (info.st_mode & 0777) == 0700, "fixture directory is not private");
#endif
}

static void strictCidrs(void)
{
    static const char *invalid[] = {"10/8",
                                    "192.168.1/24",
                                    "010.0.0.1/32",
                                    "00.0.0.0/32",
                                    "192.00.2.1/32",
                                    "192.0.02.1/32",
                                    "192.0.2.001/32",
                                    "0x0a.0.0.1/32",
                                    "256.0.0.1/32",
                                    "::ffff:010.0.0.1/128",
                                    "::ffff:192.00.2.1/128",
                                    "::ffff:192.0.02.1/128",
                                    "::ffff:192.0.2.001/128",
                                    "::ffff:192.0.2/128",
                                    "::ffff:192.0.2.256/128",
                                    "12345::/16",
                                    "1:2:3:4:5:6:7:8zz/128",
                                    "10.0.0.1x/32",
                                    "10.0.0.1/33",
                                    "::1/129",
                                    "::1/1/2",
                                    "10. 0.0.1/32",
                                    ":: 1/128",
                                    "10.0.0.1/ 32"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        char message[128];
        snprintf(message, sizeof(message), "portable CIDR parser accepted malformed address: %s", invalid[i]);
        require(! userWireGuardAllowedIpsStringValid(invalid[i]), message);
    }
    static const struct
    {
        const char *input, *expected;
        uint8_t     family, prefix;
    } valid[] = {{"0.0.0.0/0", "0.0.0.0/0", 4, 0},
                 {"1.2.3.4/32", "1.2.3.4/32", 4, 32},
                 {"255.255.255.255/32", "255.255.255.255/32", 4, 32},
                 {"192.0.2.7/32", "192.0.2.7/32", 4, 32},
                 {" \t192.0.2.123/24\r\n", "192.0.2.0/24", 4, 24},
                 {"::/0", NULL, 6, 0},
                 {"::1/128", NULL, 6, 128},
                 {"2001:db8:0:0:0:0:0:1/64", NULL, 6, 64},
                 {"::ffff:192.0.2.1/128", NULL, 6, 128},
                 {"::ffff:0.0.0.0/128", NULL, 6, 128},
                 {"::ffff:255.255.255.255/128", NULL, 6, 128}};
    for (size_t i = 0; i < ARRAY_SIZE(valid); ++i)
    {
        char     *normalized = NULL;
        ip_addr_t address, mask;
        uint8_t   family = 0, prefix = 0;
        bool      present = false;
        require(userWireGuardAllowedIpsParse(
                    valid[i].input, &normalized, &address, &mask, &family, &prefix, NULL, &present) &&
                    present && family == valid[i].family && prefix == valid[i].prefix && normalized != NULL &&
                    userWireGuardAllowedIpsStringValid(normalized),
                "portable CIDR parser rejected valid address");
        if (valid[i].expected != NULL)
            require(strcmp(normalized, valid[i].expected) == 0, "portable CIDR normalization changed network");
        memoryFree(normalized);
    }
}

static void quietLexicalParsing(void)
{
    static const struct
    {
        const char *text;
        size_t      length;
        bool        valid;
    } corpus[] = {
#define CASE(text, valid) {text, sizeof(text) - 1U, valid}
        CASE("{}", true),
        CASE("{\"x\":[1]}", true),
        CASE("[0,0,0,0,0,0,0]", true),
        CASE("\"\xc3\xa9\"", true),
        CASE("\"\\ud83d\\ude00\"", true),
        CASE("", false),
        CASE("\xef\xbb\xbf{}", false),
        CASE("{}\0suffix", false),
        CASE("{\"x\":\"\xff\"}", false),
        CASE("{\"a\":1,\"\\u0061\":2}", false),
        CASE("{\"x\":\"\\u0000\"}", false),
        CASE("\"\\ud800\"", false),
        CASE("{} trailing", false),
        CASE("{", false),
        CASE("[[[0]]]", false),
        CASE("[0,0,0,0,0,0,0,0]", false),
        CASE("01", false),
        CASE("1e999", false)
#undef CASE
    };
    const char capture_path[] = "auth-portability-private/diagnostics.log";
    FILE      *capture        = fopen(capture_path, "w+b");
    require(capture != NULL && fflush(stderr) == 0, "portable diagnostic capture setup failed");
    const int stderr_fd = fixtureFileno(stderr);
    int       original  = fixtureDup(stderr_fd);
    require(original >= 0 && fixtureDup2(fixtureFileno(capture), stderr_fd) >= 0, "portable stderr redirection failed");
    for (size_t i = 0; i < ARRAY_SIZE(corpus); ++i)
    {
        cJSON *json = configLexicalParseBounded(corpus[i].text, corpus[i].length, 2, 8);
        require((json != NULL) == corpus[i].valid, "portable diagnostic parser acceptance changed");
        cJSON_Delete(json);
        bool encoded         = configLexicalCheckEncoding(corpus[i].text, corpus[i].length);
        json                 = configLexicalParse(corpus[i].text, corpus[i].length, 2);
        bool unbounded_valid = json != NULL;
        cJSON_Delete(json);
        require(fflush(stderr) == 0, "portable diagnostic flush failed");
        long before = ftell(capture);
        require(before >= 0, "portable diagnostic position failed");
        json = configLexicalParseBoundedQuiet(corpus[i].text, corpus[i].length, 2, 8);
        require((json != NULL) == corpus[i].valid, "portable quiet bounded parser acceptance differs");
        cJSON_Delete(json);
        require(configLexicalCheckEncodingQuiet(corpus[i].text, corpus[i].length) == encoded,
                "portable quiet encoding acceptance differs");
        json = configLexicalParseQuiet(corpus[i].text, corpus[i].length, 2);
        require((json != NULL) == unbounded_valid, "portable quiet parser acceptance differs");
        cJSON_Delete(json);
        require(fflush(stderr) == 0 && ftell(capture) == before, "portable quiet parser emitted diagnostics");
    }
    require(ftell(capture) > 0, "diagnostic parser lost configuration errors");
    require(fixtureDup2(original, stderr_fd) >= 0 && fixtureClose(original) == 0, "portable stderr restoration failed");
    require(fclose(capture) == 0 && remove(capture_path) == 0, "portable diagnostic capture cleanup failed");
}

static void privateFiles(void)
{
    char  *bytes  = NULL;
    size_t length = 1;
    errno         = EIO;
    require(authenticationserverPrivateRead(primary, &bytes, &length) == kAuthenticationServerPrivateReadAbsent &&
                bytes == NULL && length == 0 &&
                authenticationserverPrivateProbe(primary) == kAuthenticationServerPrivateReadAbsent,
            "portable missing file was not classified at open");
    static const char first[] = "{\"users\":[]}\n", replacement[] = "{\"users\":[],\"fixture\":true}\n";
    require(authenticationserverPrivateWrite(primary, first, sizeof(first) - 1U), "portable private write failed");
    errno = ENOENT;
    require(authenticationserverPrivateRead(primary, &bytes, &length) == kAuthenticationServerPrivateReadSuccess &&
                length == sizeof(first) - 1U && memcmp(bytes, first, length + 1U) == 0 &&
                authenticationserverPrivateProbe(primary) == kAuthenticationServerPrivateReadSuccess,
            "portable private read lost bytes or used stale errno");
    memoryFree(bytes);
    require(authenticationserverPrivateWrite(primary, replacement, sizeof(replacement) - 1U) &&
                authenticationserverPrivateRead(primary, &bytes, &length) == kAuthenticationServerPrivateReadSuccess &&
                length == sizeof(replacement) - 1U && memcmp(bytes, replacement, length + 1U) == 0,
            "portable replacement did not publish complete bytes");
    memoryFree(bytes);
#ifndef OS_WIN
    struct stat info;
    require(stat(primary, &info) == 0 && (info.st_mode & 0777) == 0600, "portable private file permissions changed");
#endif
    require(authenticationserverPrivateRead(directory, &bytes, &length) == kAuthenticationServerPrivateReadError &&
                bytes == NULL && length == 0 &&
                authenticationserverPrivateProbe(directory) == kAuthenticationServerPrivateReadError,
            "portable directory read was treated as absence or success");
    require(authenticationserverPrivateRead("auth-portability-private/users.json/child", &bytes, &length) ==
                    kAuthenticationServerPrivateReadError &&
                bytes == NULL && length == 0,
            "portable invalid-parent open was treated as absence");
    require(authenticationserverPrivateProbe("auth-portability-private/users.json/child") ==
                kAuthenticationServerPrivateReadError,
            "portable invalid-parent probe was treated as absence");
    require(authenticationserverPrivateWrite(primary, "", 0) &&
                authenticationserverPrivateRead(primary, &bytes, &length) == kAuthenticationServerPrivateReadError &&
                bytes == NULL && length == 0 &&
                authenticationserverPrivateProbe(primary) == kAuthenticationServerPrivateReadError,
            "portable empty file was treated as absence or success");
    require(remove(primary) == 0 &&
                authenticationserverPrivateRead(primary, &bytes, &length) == kAuthenticationServerPrivateReadAbsent,
            "portable removed file was not absent");
}

static void pageProtocolMetadata(void)
{
    static const struct
    {
        uint64_t revision, position;
        size_t   emitted;
    } cases[] = {{UINT64_C(9007199254740993), UINT64_C(9007199254740995), 1}, {UINT64_MAX, UINT64_MAX, 0}};
    char cursor[65];
    for (size_t i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        authenticationserver_page_view_t view = {
            .config_revision = cases[i].revision,
            .position        = (size_t) min(cases[i].position, (uint64_t) SIZE_MAX - cases[i].emitted)};
        for (size_t j = 0; j < sizeof(view.instance_id); ++j)
            view.instance_id[j] = (uint8_t) (j * 17U);
        authenticationserverApiCursor(&view, cases[i].emitted, cursor);
        authenticationserver_api_request_t decoded = {0};
        require(authenticationserverApiCursorDecode(cursor, &decoded) && decoded.has_cursor &&
                    decoded.revision == cases[i].revision &&
                    decoded.position == (uint64_t) view.position + cases[i].emitted &&
                    memcmp(decoded.instance_id, view.instance_id, sizeof(view.instance_id)) == 0,
                "portable page cursor lost exact 64-bit metadata");
    }
    authenticationserver_api_request_t decoded = {0};
    require(authenticationserverApiCursorDecode("00112233445566778899aabbccddeeffffffffffffffffffffffffffffffffff",
                                                &decoded) &&
                decoded.revision == UINT64_MAX && decoded.position == UINT64_MAX,
            "portable cursor decoder narrowed uint64 metadata");
    cursor[0] = 'A';
    require(! authenticationserverApiCursorDecode(cursor, &decoded), "portable cursor accepted uppercase hex");
    cursor[0] = 'g';
    require(! authenticationserverApiCursorDecode(cursor, &decoded), "portable cursor accepted nonhex character");
    cursor[0]  = '0';
    cursor[63] = '\0';
    require(! authenticationserverApiCursorDecode(cursor, &decoded) &&
                ! authenticationserverApiCursorDecode(NULL, &decoded),
            "portable cursor accepted missing or short text");
    static const struct
    {
        const char *text;
        uint64_t    value;
    } valid[] = {{"0", 0}, {"9007199254740993", UINT64_C(9007199254740993)}, {"18446744073709551615", UINT64_MAX}};
    for (size_t i = 0; i < ARRAY_SIZE(valid); ++i)
    {
        uint64_t value;
        require(authenticationserverApiUnsignedDecimal(valid[i].text, &value) && value == valid[i].value,
                "portable page decimal lost exact unsigned value");
    }
    static const char *invalid[] = {
        NULL, "", "00", "01", "+1", "-1", " 1", "1 ", "1.0", "1e0", "18446744073709551616", "999999999999999999999"};
    for (size_t i = 0; i < ARRAY_SIZE(invalid); ++i)
    {
        uint64_t value;
        require(! authenticationserverApiUnsignedDecimal(invalid[i], &value),
                "portable page decimal accepted invalid text");
    }
}

static void boundedCredentialRow(void)
{
    users_t users;
    require(usersCreate(&users), "portable row collection failed");
    cJSON  *source = cJSON_CreateObject();
    discard cJSON_AddStringToObject(source, "id", "18446744073709551615");
    discard cJSON_AddStringToObject(source, "password", "portable-row");
    discard cJSON_AddStringToObject(source, "notes", "quote \" slash \\ line\n\xc3\xa9");
    require(usersFeedJsonRequiredIds(&users, source), "portable credential row import failed");
    authenticationserverWipeJsonStrings(source);
    cJSON_Delete(source);
    cJSON *row     = NULL;
    size_t encoded = 0;
    require(usersCopyFullUserJsonAt(&users, 0, 4096, &row, &encoded) == kUserPublicOk && encoded != 0,
            "portable credential row export failed");
    char *text = cJSON_PrintUnformatted(row);
    require(strlen(text) == encoded &&
                strcmp(cJSON_GetObjectItemCaseSensitive(row, "password")->valuestring, "portable-row") == 0,
            "portable row size or full credential output changed");
    memorySecureZero(text, encoded);
    cJSON_free(text);
    authenticationserverWipeJsonStrings(row);
    cJSON_Delete(row);
    size_t exact = 0;
    require(usersCopyFullUserJsonAt(&users, 0, encoded, &row, &exact) == kUserPublicOk && exact == encoded,
            "portable row equality boundary refused");
    authenticationserverWipeJsonStrings(row);
    cJSON_Delete(row);
    require(usersCopyFullUserJsonAt(&users, 0, encoded - 1U, &row, &exact) == kUserPublicTooLarge && row == NULL &&
                exact == 0,
            "portable row one-byte-under boundary materialized output");
    usersDestroy(&users);
}

int main(void)
{
    testCaseSet("authentication_portability_test");
    require(createNetworkLogger(NULL, false) != NULL && wCryptoGlobalInit() == kWCryptoOk,
            "portable logger/crypto initialization failed");
    createPrivateDirectory();
    strictCidrs();
    quietLexicalParsing();
    privateFiles();
    pageProtocolMetadata();
    boundedCredentialRow();
#ifdef OS_WIN
    require(RemoveDirectoryA(directory), "portable private-directory cleanup failed");
#else
    require(rmdir(directory) == 0, "portable private-directory cleanup failed");
#endif
    wCryptoGlobalCleanup();
    networkloggerDestroy();
    return 0;
}
