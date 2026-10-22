/*
 * Covers: tun linux command; the explicit inputs, callbacks and expected results below define this
 * suite.
 * Setup: Real implementation entry points with the explicit substituted OS/allocation/timer boundary
 * shown below.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.tun_linux_command_unit
 */
/* Exercise the real TUN command adapter and default-route discovery with
 * in-memory proc route tables and a fixed interface-index lookup. No route or
 * interface is changed. */
#include "devices/tun/tun_linux_internal.h"
#include "loggers/internal_logger.h"
#include "wwapi.h"

#include <net/if.h>
#include <sys/ioctl.h>

static const char *routes_v4;
static const char *routes_v6;

FILE *__real_fopen(const char *path, const char *mode);
FILE *__wrap_fopen(const char *path, const char *mode);
int   __wrap_ioctl(int fd, unsigned long request, ...);

FILE *__wrap_fopen(const char *path, const char *mode)
{
    const char *contents;
    if (strcmp(path, "/proc/net/route") == 0)
        contents = routes_v4;
    else if (strcmp(path, "/proc/net/ipv6_route") == 0)
        contents = routes_v6;
    else
        return __real_fopen(path, mode);
    if (contents == NULL)
    {
        errno = ENOENT;
        return NULL;
    }
    FILE *stream = tmpfile();
    if (stream == NULL || fputs(contents, stream) == EOF)
        abort();
    rewind(stream);
    return stream;
}

int __wrap_ioctl(int fd, unsigned long request, ...)
{
    discard fd;
    if (request != SIOCGIFINDEX)
        abort();
    va_list args;
    va_start(args, request);
    struct ifreq *ifr = va_arg(args, struct ifreq *);
    va_end(args);
    if (strcmp(ifr->ifr_name, "eth0") == 0)
        ifr->ifr_ifindex = 9;
    else if (strcmp(ifr->ifr_name, "ppp0") == 0)
        ifr->ifr_ifindex = 17;
    else if (strcmp(ifr->ifr_name, "cell0") == 0)
        ifr->ifr_ifindex = 23;
    else
    {
        errno = ENODEV;
        return -1;
    }
    return 0;
}

#define V4_HEADER "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n"
#define V6_ZERO   "00000000000000000000000000000000"
#define V6_DEFAULT(iface, metric, flags)                                                                               \
    V6_ZERO " 00 " V6_ZERO " 00 " V6_ZERO " " metric " 00000000 00000000 " flags " " iface "\n"

static void testDefaultRoutes(void)
{
    static const struct
    {
        const char *name;
        const char *v4;
        const char *v6;
        const char *ifname;
        uint32_t    v4_index;
        uint32_t    v6_index;
    } cases[] = {
        {"gateway IPv4", V4_HEADER "eth0 00000000 0100000A 0003 0 0 100 00000000\n", "", "eth0", 9, 0},
        {"direct IPv4", V4_HEADER "ppp0 00000000 00000000 0001 0 0 100 00000000\n", "", "ppp0", 17, 0},
        {"usable IPv4 metric ordering",
         V4_HEADER "bad0 00000000 00000000 0201 0 0 0 00000000\n"
                   "bad0 00000000 00000000 0000 0 0 0 00000000\n"
                   "bad0 0000000A 00000000 0001 0 0 0 00FFFFFF\n"
                   "eth0 00000000 0100000A 0003 0 0 100 00000000\n"
                   "ppp0 00000000 00000000 0001 0 0 20 00000000\n"
                   "cell0 00000000 00000000 0001 0 0 20 00000000\n",
         "",
         "ppp0",
         17,
         0},
        {"maximum IPv4 metric", V4_HEADER "ppp0 00000000 00000000 0001 0 0 4294967295 00000000\n", "", "ppp0", 17, 0},
        {"gateway IPv6", V4_HEADER, V6_DEFAULT("eth0", "00000064", "00000003"), "eth0", 0, 9},
        {"direct IPv6", V4_HEADER, V6_DEFAULT("ppp0", "00000064", "00000001"), "ppp0", 0, 17},
        {"usable IPv6 metric ordering",
         V4_HEADER,
         V6_DEFAULT("bad0", "00000000", "00000201") V6_DEFAULT(
             "bad0", "00000000", "00000000") "20010db8000000000000000000000000 40 " V6_ZERO " 00 " V6_ZERO
                                             " 00000000 0 0 00000001 bad0\n" V6_ZERO
                                             " 00 20010db8000000000000000000000000 40 " V6_ZERO
                                             " 00000000 0 0 00000001 bad0\n" V6_DEFAULT("eth0", "00000064", "00000003")
                                                 V6_DEFAULT("ppp0", "00000014", "00000001")
                                                     V6_DEFAULT("cell0", "00000014", "00000001"),
         "ppp0",
         0,
         17},
        {"maximum IPv6 metric", V4_HEADER, V6_DEFAULT("cell0", "ffffffff", "00000001"), "cell0", 0, 23},
        {"both families",
         V4_HEADER "ppp0 00000000 00000000 0001 0 0 1 00000000\n",
         V6_DEFAULT("cell0", "00000001", "00000001"),
         "ppp0",
         17,
         23},
        {"empty routes", V4_HEADER, "", "", 0, 0},
        {"missing proc routes", NULL, NULL, "", 0, 0},
        {"only unusable routes",
         V4_HEADER "bad0 00000000 00000000 0201 0 0 0 00000000\n",
         V6_DEFAULT("bad0", "00000000", "00000201"),
         "",
         0,
         0},
        {"interface disappeared", V4_HEADER "gone0 00000000 00000000 0001 0 0 1 00000000\n", "", "", 0, 0},
    };
    for (unsigned i = 0; i < ARRAY_SIZE(cases); ++i)
    {
        routes_v4 = cases[i].v4;
        routes_v6 = cases[i].v6;
        tun_default_route_t selected;
        const bool          found = tundeviceDetectDefaultInterface(&selected);
        if (found != (cases[i].v4_index != 0 || cases[i].v6_index != 0) ||
            selected.have_v4 != (cases[i].v4_index != 0) || selected.have_v6 != (cases[i].v6_index != 0) ||
            selected.ifindex_v4 != cases[i].v4_index || selected.ifindex_v6 != cases[i].v6_index ||
            strcmp(selected.ifname, cases[i].ifname) != 0)
        {
            fprintf(stderr, "default-route selection failed: %s\n", cases[i].name);
            abort();
        }
    }
}

static unsigned int calls;
static unsigned int drops;
static int          outcome;
static char         diagnostic[512];

static void captureDiagnostic(int level, const char *bytes, int length)
{
    discard level;
    size_t  count = min((size_t) max(length, 0), sizeof(diagnostic) - 1U);
    memcpy(diagnostic, bytes, count);
    diagnostic[count] = '\0';
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
void __wrap_procCommandResultDrop(proc_command_result_t *out);
void __real_procCommandResultDrop(proc_command_result_t *out);

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    if (strcmp(file, "fixture-tool") != 0 || strcmp(argv[0], "fixture-tool") != 0 ||
        strcmp(argv[1], "literal ; $HOME") != 0 || argv[2] != NULL || options->timeout_ms != 7000 ||
        options->terminate_grace_ms != 250 || options->max_output_bytes != 64 * 1024)
    {
        abort();
    }
    ++calls;
    memset(out, 0, sizeof(*out));
    out->exit_code        = outcome == 1 ? 127 : outcome == 5 ? 3 : outcome == 6 ? 143 : 0;
    out->timed_out        = outcome == 2;
    out->output_too_large = outcome == 3;
    out->spawn_failed     = outcome == 4;
    out->output           = memoryAllocate(2);
    strcpy(out->output, "x");
    out->output_len = 1;
    return outcome == 0;
}

void __wrap_procCommandResultDrop(proc_command_result_t *out)
{
    if (out->output == NULL)
    {
        abort();
    }
    ++drops;
    __real_procCommandResultDrop(out);
}

int main(void)
{
    testDefaultRoutes();
    logger_t *logger = loggerCreate();
    if (logger == NULL)
        abort();
    loggerSetHandler(logger, captureDiagnostic);
    setInternalLogger(logger);
    const char *expected[] = {
        "", "status 127", "deadline", "output limit", "supervisor failed", "status 3", "status 143"};
    const char *const argv[] = {"fixture-tool", "literal ; $HOME", NULL};
    for (outcome = 0; outcome <= 6; ++outcome)
    {
        diagnostic[0] = '\0';
        int status    = tunLinuxRunCommandForTest("fixture-tool", argv);
        if (status != (outcome == 0                     ? 0
                       : (outcome == 1 || outcome == 5) ? -1
                                                        : -2) ||
            strstr(diagnostic, expected[outcome]) == NULL)
        {
            abort();
        }
    }
    if (calls != 7 || drops != 7)
    {
        abort();
    }
    internaloggerDestroy();
    return 0;
}
