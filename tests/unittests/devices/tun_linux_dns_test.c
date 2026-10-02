/*
 * Covers: tun linux dns; the explicit inputs, callbacks and expected results below define this suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Cases: testRoundtrip, testFailedApply, testRestoreRetry, testForeignChange, testUnavailableBaseline,
 * testIdentityAndReadFailure, testInterveningChangeAndNoop
 * Checks: Assertion labels include: unexpected interface mutation; reply serialization; a(sb); bad setter
 * count
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tun_linux_dns_unit
 */
/* Real Linux DNS configuration with inert command and interface-index seams. */
#include "cJSON.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)
#include "devices/tun/tun_linux_private.h"
#include "wwapi.h"
#include <net/if.h>
#include <sys/ioctl.h>

static cJSON       *settings[2];
static unsigned int writes[2];
static unsigned int results, drops;
static int          interface_index = 42;
static int          fail_field      = -1;
static int fail_kind; /* 1: nonzero, 2: timeout before, 3: timeout after, 4: overflow after, 5: parent failure after. */
static int fail_read_field = -1;
static const char *malformed_reply;
static bool        change_domain_after_dns;
static bool        private_bus;


int  __wrap_ioctl(int fd, unsigned long request, ...);
bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
bool __real_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    discard fd;
    require(request == SIOCGIFINDEX, "unexpected interface mutation");
    va_list args;
    va_start(args, request);
    struct ifreq *ifr = va_arg(args, struct ifreq *);
    va_end(args);
    require(strcmp(ifr->ifr_name, "fixture-tun") == 0, "wrong interface");
    ifr->ifr_ifindex = interface_index;
    return 0;
}

static void reply(proc_command_result_t *out, const char *type, const cJSON *data)
{
    cJSON *root = cJSON_CreateObject();
    require(root && cJSON_AddStringToObject(root, "type", type) &&
                cJSON_AddItemToObject(root, "data", cJSON_Duplicate(data, true)),
            "reply allocation");
    char *text = cJSON_PrintUnformatted(root);
    require(text != NULL, "reply serialization");
    out->output     = stringDuplicate(text);
    out->output_len = strlen(text);
    cJSON_free(text);
    cJSON_Delete(root);
}

static cJSON *decodeWrite(const char *const argv[], unsigned int field)
{
    require(strcmp(argv[10], field == 0 ? "a(iayqs)" : "a(sb)") == 0, "wrong setter signature");
    unsigned int count = (unsigned int) strtoul(argv[11], NULL, 10), cursor = 12;
    cJSON       *array = cJSON_CreateArray();
    require(array != NULL && count <= 128, "bad setter count");
    for (unsigned int i = 0; i < count; ++i)
    {
        cJSON *entry = cJSON_CreateArray();
        require(entry && cJSON_AddItemToArray(array, entry), "entry allocation");
        if (field == 1)
        {
            require(cJSON_AddItemToArray(entry, cJSON_CreateString(argv[cursor++])), "domain allocation");
            require(strcmp(argv[cursor], "true") == 0 || strcmp(argv[cursor], "false") == 0, "domain boolean");
            require(cJSON_AddItemToArray(entry, cJSON_CreateBool(strcmp(argv[cursor++], "true") == 0)), "boolean");
            continue;
        }
        require(cJSON_AddItemToArray(entry, cJSON_CreateNumber(strtoul(argv[cursor++], NULL, 10))), "family");
        unsigned int length = (unsigned int) strtoul(argv[cursor++], NULL, 10);
        require(length == 4 || length == 16, "address byte count");
        cJSON *address = cJSON_CreateArray();
        require(address && cJSON_AddItemToArray(entry, address), "address");
        for (unsigned int j = 0; j < length; ++j)
            require(cJSON_AddItemToArray(address, cJSON_CreateNumber(strtoul(argv[cursor++], NULL, 10))), "byte");
        require(cJSON_AddItemToArray(entry, cJSON_CreateNumber(strtoul(argv[cursor++], NULL, 10))), "port");
        require(cJSON_AddItemToArray(entry, cJSON_CreateString(argv[cursor++])), "server name");
    }
    require(argv[cursor] == NULL, "unexpected setter arguments");
    return array;
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    if (private_bus)
        return __real_procRunArgvWithDeadline(file, argv, options, out);
    require(strcmp(file, "busctl") == 0 && strcmp(argv[0], file) == 0, "attached DNS used blanket revert/resolvectl");
    require(options->timeout_ms == 7000 && options->terminate_grace_ms == 250 && options->max_output_bytes == 65536,
            "command lost deadline/output bounds");
    require(strcmp(argv[1], "--system") == 0 && strcmp(argv[4], "--") == 0 &&
                strcmp(argv[6], "org.freedesktop.resolve1") == 0,
            "command scope");
    ++results;
    *out = (proc_command_result_t) {.exit_code = 0};
    if (strcmp(argv[9], "GetLink") == 0)
    {
        require(strcmp(argv[5], "call") == 0 && strcmp(argv[10], "i") == 0 && strcmp(argv[11], "42") == 0,
                "GetLink identity");
        cJSON *data = cJSON_Parse("[\"/org/freedesktop/resolve1/link/_342\"]");
        reply(out, "o", data);
        cJSON_Delete(data);
        return true;
    }
    require(strcmp(argv[7], "/org/freedesktop/resolve1/link/_342") == 0 &&
                strcmp(argv[8], "org.freedesktop.resolve1.Link") == 0,
            "wrong link object");
    const bool read = strcmp(argv[5], "get-property") == 0;
    const bool dns  = strcmp(argv[9], read ? "DNSEx" : "SetDNSEx") == 0;
    require(dns || strcmp(argv[9], read ? "Domains" : "SetDomains") == 0, "unrelated resolver property changed");
    unsigned int field = dns ? 0 : 1;
    if (read)
    {
        require(strcmp(argv[2], "--json=short") == 0 && argv[10] == NULL, "structured property read");
        if (fail_read_field == (int) field)
        {
            fail_read_field = -1;
            out->timed_out  = true;
            return false;
        }
        if (malformed_reply != NULL)
        {
            out->output     = stringDuplicate(malformed_reply);
            out->output_len = strlen(out->output);
            malformed_reply = NULL;
            return true;
        }
        reply(out, dns ? "a(iayqs)" : "a(sb)", settings[field]);
        return true;
    }
    require(strcmp(argv[5], "call") == 0 && strcmp(argv[3], "--allow-interactive-authorization=no") == 0,
            "setter can prompt or used wrong verb");
    ++writes[field];
    int failure = fail_field == (int) field ? fail_kind : 0;
    if (failure != 0)
        fail_field = -1;
    cJSON *value = decodeWrite(argv, field);
    if (failure == 1 || failure == 2)
        cJSON_Delete(value);
    else
    {
        cJSON_Delete(settings[field]);
        settings[field] = value;
    }
    if (field == 0 && change_domain_after_dns)
    {
        change_domain_after_dns = false;
        cJSON_Delete(settings[1]);
        settings[1] = cJSON_Parse("[[\"external.corp\",false]]");
    }
    out->exit_code        = failure == 1 ? 1 : 0;
    out->timed_out        = failure == 2 || failure == 3;
    out->output_too_large = failure == 4;
    out->spawn_failed     = failure == 5;
    return failure == 0;
}

void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    ++drops;
    __real_procCommandResultDrop(out);
}

static const char *const requested[] = {"1.1.1.1", "8.8.8.8"};
static const char *const baselines[] = {
    "[[2,[10,0,0,53],5353,\"dns.corp\"],[10,[32,1,13,184,0,0,0,0,0,0,0,0,0,0,0,53],853,\"v6.corp\"]]",
    "[[\"z.corp\",false],[\"a.corp\",false],[\"vpn.corp\",true]]"};

static void reset(bool empty)
{
    for (unsigned int i = 0; i < 2; ++i)
    {
        cJSON_Delete(settings[i]);
        settings[i] = cJSON_Parse(empty ? "[]" : baselines[i]);
        require(settings[i] != NULL, "fixture baseline");
        writes[i] = 0;
    }
    interface_index = 42;
    fail_field = fail_read_field = -1;
    fail_kind                    = 0;
    malformed_reply              = NULL;
    change_domain_after_dns      = false;
}

static void requireBaseline(bool empty)
{
    for (unsigned int i = 0; i < 2; ++i)
    {
        cJSON *expected = cJSON_Parse(empty ? "[]" : baselines[i]);
        require(cJSON_Compare(settings[i], expected, true), "baseline values/order/port/name were not restored");
        cJSON_Delete(expected);
    }
}

static tun_device_t device(void)
{
    return (tun_device_t) {.name = (char *) "fixture-tun", .interface_preexisting = true};
}

static void testRoundtrip(bool empty)
{
    reset(empty);
    tun_device_t tdev = device();
    require(tundeviceSetDnsServers(&tdev, requested, 2), "attached-interface DNS setup failed");
    require(tundeviceDnsNeedsCleanup(&tdev), "successful mutations lost cleanup responsibility");
    require(tundeviceClearDnsServers(&tdev), "baseline restoration failed");
    require(! tundeviceDnsNeedsCleanup(&tdev) && tdev.dns_snapshot == NULL, "settled snapshot retained");
    requireBaseline(empty);
    require(writes[0] == 2 && writes[1] == 2, "setup/restoration did not touch exactly the two owned fields");
    require(tundeviceClearDnsServers(&tdev) && writes[0] == 2 && writes[1] == 2, "cleanup not idempotent");
}

static void testFailedApply(unsigned int field, int kind)
{
    reset(false);
    tun_device_t tdev = device();
    fail_field        = (int) field;
    fail_kind         = kind;
    require(! tundeviceSetDnsServers(&tdev, requested, 2), "failed setter accepted startup");
    if (field == 0)
        require(writes[1] == 0, "startup continued after server failure");
    require(tundeviceClearDnsServers(&tdev), "partial/uncertain setup did not restore baseline");
    requireBaseline(false);
}

static void testRestoreRetry(void)
{
    reset(false);
    tun_device_t tdev = device();
    require(tundeviceSetDnsServers(&tdev, requested, 2), "retry setup");
    fail_field = 1;
    fail_kind  = 2;
    require(! tundeviceClearDnsServers(&tdev) && tundeviceDnsNeedsCleanup(&tdev), "failed restore forgotten");
    require(writes[0] == 2 && writes[1] == 2, "one failed restore blocked independent cleanup");
    require(tundeviceClearDnsServers(&tdev) && writes[0] == 2 && writes[1] == 3,
            "retry rewrote already restored field");
    requireBaseline(false);
    for (int kind = 3; kind <= 5; ++kind)
    {
        reset(false);
        tdev = device();
        require(tundeviceSetDnsServers(&tdev, requested, 2), "unknown restore setup");
        fail_field = 1;
        fail_kind  = kind;
        require(tundeviceClearDnsServers(&tdev), "committed uncertain restoration not reconciled");
        requireBaseline(false);
    }
}

static void testForeignChange(void)
{
    reset(false);
    tun_device_t tdev = device();
    require(tundeviceSetDnsServers(&tdev, requested, 2), "foreign-change setup");
    cJSON_Delete(settings[0]);
    settings[0] = cJSON_Parse("[[2,[9,9,9,9],0,\"\"]]");
    require(! tundeviceClearDnsServers(&tdev) && writes[0] == 1 && writes[1] == 2,
            "cleanup overwrote foreign DNS or skipped independent domains");
    require(! tundeviceClearDnsServers(&tdev) && writes[0] == 1 && writes[1] == 2, "retry clobbered foreign DNS");
    cJSON_Delete(settings[0]);
    settings[0] = cJSON_Parse(baselines[0]);
    require(tundeviceClearDnsServers(&tdev) && writes[0] == 1, "already restored field was rewritten");
    requireBaseline(false);
}

static void testUnavailableBaseline(void)
{
    const char *bad[] = {"not json",
                         "{\"type\":\"a(iayqs)\",\"data\":[[2,[1,1,1,999],0,\"\"]]}",
                         "{\"type\":\"a(iayqs)\",\"data\":[[2,[1,1,1,1],65536,\"\"]]}",
                         "{\"type\":\"a(iayqs)\",\"data\":[[2,[1,1,1,1],0,\"x\\u0000y\"]]}",
                         "{\"type\":\"a(sb)\",\"data\":[]}"};
    for (unsigned int i = 0; i < sizeof(bad) / sizeof(bad[0]) + 2; ++i)
    {
        reset(false);
        tun_device_t tdev = device();
        if (i < sizeof(bad) / sizeof(bad[0]))
            malformed_reply = bad[i];
        else
            fail_read_field = (int) (i - sizeof(bad) / sizeof(bad[0]));
        require(! tundeviceSetDnsServers(&tdev, requested, 2) && ! tundeviceDnsNeedsCleanup(&tdev) &&
                    tdev.dns_snapshot == NULL && writes[0] == 0 && writes[1] == 0,
                "unsafe baseline accepted");
        requireBaseline(false);
    }
}

static void testIdentityAndReadFailure(void)
{
    reset(false);
    tun_device_t tdev = device();
    require(tundeviceSetDnsServers(&tdev, requested, 2), "identity setup");
    interface_index = 43;
    require(! tundeviceClearDnsServers(&tdev) && writes[0] == 1 && writes[1] == 1, "replacement link mutated");
    interface_index = 42;
    fail_read_field = 1;
    require(! tundeviceClearDnsServers(&tdev) && writes[0] == 2 && writes[1] == 1, "unreadable field mutated");
    require(tundeviceClearDnsServers(&tdev), "read/identity recovery failed");
    requireBaseline(false);
}

static void testInterveningChangeAndNoop(void)
{
    reset(false);
    tun_device_t tdev       = device();
    change_domain_after_dns = true;
    require(! tundeviceSetDnsServers(&tdev, requested, 2) && writes[1] == 0,
            "setup overwrote domains changed since baseline capture");
    require(tundeviceClearDnsServers(&tdev) && writes[0] == 2 && writes[1] == 0,
            "cleanup touched a field that setup never changed");
    require(strcmp(cJSON_GetArrayItem(cJSON_GetArrayItem(settings[1], 0), 0)->valuestring, "external.corp") == 0,
            "foreign domain was lost");
    reset(true);
    cJSON_Delete(settings[0]);
    cJSON_Delete(settings[1]);
    settings[0] = cJSON_Parse("[[2,[1,1,1,1],0,\"\"],[2,[8,8,8,8],0,\"\"]]");
    settings[1] = cJSON_Parse("[[\".\",true]]");
    tdev        = device();
    require(tundeviceSetDnsServers(&tdev, requested, 2) && ! tundeviceDnsNeedsCleanup(&tdev),
            "no-op acquired ownership");
    require(tundeviceClearDnsServers(&tdev) && writes[0] == 0 && writes[1] == 0 && tdev.dns_snapshot == NULL,
            "no-op setup/cleanup rewrote existing values");
}

int main(void)
{
    testCaseSet("tun_linux_dns_test");
    if (getenv("WW_TUN_DNS_TEST_PRIVATE_BUS") != NULL)
    {
        private_bus       = true;
        tun_device_t tdev = device();
        require(tundeviceSetDnsServers(&tdev, requested, 2), "private-bus setup");
        require(tundeviceClearDnsServers(&tdev) && ! tundeviceDnsNeedsCleanup(&tdev), "private-bus restoration");
        return 0;
    }

    testRoundtrip(true);
    testRoundtrip(false);
    for (unsigned int field = 0; field < 2; ++field)
        for (int kind = 1; kind <= 5; ++kind)
            testFailedApply(field, kind);
    testRestoreRetry();
    testForeignChange();
    testUnavailableBaseline();
    testIdentityAndReadFailure();
    testInterveningChangeAndNoop();
    require(results == drops, "command result not dropped exactly once");
    cJSON_Delete(settings[0]);
    cJSON_Delete(settings[1]);
    puts("Linux attached-interface DNS tests passed");
    return 0;
}
