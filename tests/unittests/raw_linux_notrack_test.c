#include "devices/raw/raw_linux_internal.h"
#include "wproc.h"

#include <sys/socket.h>

static uint32_t     random_word;
static bool         installed;
static bool         fail_snapshot;
static bool         fail_socket_mark;
static bool         fail_insert;
static bool         fail_delete;
static bool         fail_inspection;
static bool         commit_on_failure;
static unsigned int command_count;
static unsigned int mark_count;
static char         inserted_mark[32];
static char         inserted_comment[48];

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

uint32_t __wrap_fastRand32(void);
uint64_t __wrap_fastRand64(void);
uint32_t __wrap_fastRand32(void)
{
    return random_word++;
}
uint64_t __wrap_fastRand64(void)
{
    return UINT64_C(0xabcdef0123456789);
}

int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length);
int __wrap_setsockopt(int fd, int level, int option, const void *value, socklen_t length)
{
    require(fd == 7001 && level == SOL_SOCKET && option == SO_MARK && length == sizeof(uint32_t),
            "NOTRACK set an unexpected socket option");
    require(*(const uint32_t *) value >= UINT32_C(0x00010000), "automatic mark used the conventional low range");
    ++mark_count;
    errno = EPERM;
    return fail_socket_mark ? -1 : 0;
}

bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out);
bool __wrap_procRunArgvWithDeadline(const char *file, const char *const argv[], const proc_command_options_t *options,
                                    proc_command_result_t *out)
{
    ++command_count;
    *out = (proc_command_result_t) {0};
    require(strcmp(file, argv[0]) == 0, "command executable differs from argv[0]");
    require(options->timeout_ms == 7000 && options->terminate_grace_ms == 250, "NOTRACK commands lost their deadline");
    if (strcmp(file, "iptables-save") == 0 || strcmp(file, "ip") == 0)
    {
        require(options->max_output_bytes == 1024 * 1024, "mark inspection output is not bounded");
        if (strcmp(file, "ip") == 0)
        {
            require(strcmp(argv[1], "-4") == 0 && strcmp(argv[2], "rule") == 0 && strcmp(argv[3], "show") == 0 &&
                        argv[4] == NULL,
                    "mark selection did not inspect IPv4 policy routing");
        }
        out->output    = stringDuplicate("");
        out->timed_out = fail_snapshot;
        return ! fail_snapshot;
    }
    require(strcmp(file, "iptables") == 0 && strcmp(argv[1], "-w") == 0 && strcmp(argv[2], "5") == 0 &&
                strcmp(argv[3], "-t") == 0 && strcmp(argv[4], "raw") == 0 && strcmp(argv[6], "OUTPUT") == 0,
            "NOTRACK rule has the wrong table, hook, or lock wait");
    if (strcmp(argv[5], "-S") == 0)
    {
        char rules[256];
        snprintf(rules,
                 sizeof(rules),
                 "-P OUTPUT ACCEPT\n%s%s\n",
                 installed ? "-A OUTPUT --comment " : "",
                 installed ? inserted_comment : "");
        out->output       = stringDuplicate(rules);
        out->spawn_failed = fail_inspection;
        return ! fail_inspection;
    }

    require(options->max_output_bytes == 64 * 1024, "rule mutation output is not bounded");
    require(strcmp(argv[7], "-m") == 0 && strcmp(argv[8], "mark") == 0 && strcmp(argv[9], "--mark") == 0 &&
                strstr(argv[10], "/0xffffffff") != NULL && strcmp(argv[11], "-m") == 0 &&
                strcmp(argv[12], "comment") == 0 && strcmp(argv[13], "--comment") == 0 &&
                strncmp(argv[14], "WWRAW_NOTRACK_", 14) == 0 && strcmp(argv[15], "-j") == 0 &&
                strcmp(argv[16], "CT") == 0 && strcmp(argv[17], "--notrack") == 0 && argv[18] == NULL,
            "NOTRACK mutation did not use an exact mark and owned comment");
    if (strcmp(argv[5], "-I") == 0)
    {
        require(! installed, "NOTRACK installed a duplicate rule");
        snprintf(inserted_mark, sizeof(inserted_mark), "%s", argv[10]);
        snprintf(inserted_comment, sizeof(inserted_comment), "%s", argv[14]);
        installed      = ! fail_insert || commit_on_failure;
        out->timed_out = fail_insert;
        return ! fail_insert;
    }
    require(strcmp(argv[5], "-D") == 0 && strcmp(argv[10], inserted_mark) == 0 &&
                strcmp(argv[14], inserted_comment) == 0,
            "NOTRACK cleanup did not target exactly its installed rule");
    if (! installed)
    {
        out->exit_code = 1;
        return false;
    }
    if (! fail_delete || commit_on_failure)
    {
        installed = false;
    }
    out->output_too_large = fail_delete;
    return ! fail_delete;
}

static void reset(void)
{
    random_word = 0x12345678;
    installed = fail_snapshot = fail_socket_mark = fail_insert = fail_delete = fail_inspection = false;
    commit_on_failure                                                                          = false;
    command_count = mark_count = 0;
}

static void testSelection(void)
{
    uint32_t mark = 0;
    random_word   = 0x12345678;
    require(rawLinuxSelectNotrackMark("", "", &mark) && mark == UINT32_C(0x92345678),
            "selection did not prefer a random high mark");
    random_word = 0x12345678;
    require(rawLinuxSelectNotrackMark("-A OUTPUT -m mark --mark 0x92345678\n", "", &mark) &&
                mark != UINT32_C(0x92345678),
            "selection reused an existing exact mark");
    random_word = 0x12345678;
    require(rawLinuxSelectNotrackMark("-A OUTPUT -j MARK --set-xmark 0x92345678/0xffffffff\n", "", &mark) &&
                mark != UINT32_C(0x92345678),
            "selection reused a mark assigned by another program");
    random_word = 0x12345678;
    require(rawLinuxSelectNotrackMark(
                "-A OUTPUT ! --mark 0x0/0xff\n", "100: from all not fwmark 0x0/0x80000000 lookup 100\n", &mark) &&
                (mark & UINT32_C(0x800000ff)) == 0 && mark >= 0x10000,
            "selection changed masked zero/inverted routing matches");
    random_word = 0x12345678;
    require(rawLinuxSelectNotrackMark("-A OUTPUT --comment \"ignore --mark broken\"\n", "", &mark),
            "selection interpreted a quoted comment as a mark rule");
    random_word = 0x12345678;
    require(rawLinuxSelectNotrackMark("", "100: fwmark 0x80000001/0x80000000 prohibit\n", &mark) &&
                (mark & UINT32_C(0x80000000)) == 0,
            "selection failed to mask a routing value or fall back from the reserved high half");
    require(! rawLinuxSelectNotrackMark("", "100: fwmark 0x0/0xffffffff lookup 100\n", &mark),
            "selection changed an exact unmarked routing policy");
    require(! rawLinuxSelectNotrackMark("--mark 4294967296\n", "", &mark), "selection accepted mark overflow");
    require(! rawLinuxSelectNotrackMark("", "100: fwmark 0x1/bad lookup 100\n", &mark),
            "selection accepted a malformed mask");
}

static void testRules(void)
{
    reset();
    char         name[] = "notrack-test";
    raw_device_t rdev   = {.name = name, .socket = 7001};
    require(rawLinuxNotrackInstall(&rdev) && rawLinuxNotrackRemove(&rdev) && command_count == 0 && mark_count == 0,
            "disabled bypass modified the firewall or socket");
    rdev.bypass_conntrack = true;
    require(rawLinuxNotrackInstall(&rdev) && installed && rdev.notrack_rule_pending && mark_count == 1,
            "enabled bypass did not install its rule and socket mark");
    require(rawLinuxNotrackRemove(&rdev) && ! installed && ! rdev.notrack_rule_pending,
            "normal cleanup retained NOTRACK");

    reset();
    fail_snapshot = true;
    require(! rawLinuxNotrackInstall(&rdev) && mark_count == 0 && ! rdev.notrack_rule_pending,
            "failed inspection still changed the socket or firewall");
    reset();
    fail_socket_mark = true;
    require(! rawLinuxNotrackInstall(&rdev) && ! installed && ! rdev.notrack_rule_pending,
            "SO_MARK failure still installed a rule");

    for (unsigned int committed = 0; committed < 2; ++committed)
    {
        reset();
        fail_insert       = true;
        commit_on_failure = committed != 0;
        require(! rawLinuxNotrackInstall(&rdev) && rdev.notrack_rule_pending,
                "uncertain insertion discarded cleanup ownership");
        require(rawLinuxNotrackRemove(&rdev) && ! installed && ! rdev.notrack_rule_pending,
                "uncertain insertion did not roll back");
    }

    reset();
    require(rawLinuxNotrackInstall(&rdev), "cleanup fixture install failed");
    fail_delete = fail_inspection = true;
    require(! rawLinuxNotrackRemove(&rdev) && installed && rdev.notrack_rule_pending,
            "failed deletion/inspection lost rule ownership");
    fail_inspection = false;
    require(! rawLinuxNotrackRemove(&rdev) && rdev.notrack_rule_pending,
            "inspection of a still-present rule reported cleanup success");
    commit_on_failure = true;
    require(rawLinuxNotrackRemove(&rdev) && ! installed && ! rdev.notrack_rule_pending,
            "uncertain committed deletion was not reconciled");
}

int main(void)
{
    testSelection();
    testRules();
    return 0;
}
