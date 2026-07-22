#include "socket_manager_iptables_recovery.h"

#include "wproc.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

#if defined(OS_LINUX)
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

typedef struct iptables_candidate_s
{
    uint64_t token;
    int      family;
    char     chain_name[kSocketManagerIptablesChainNameBufLen];
    size_t   prerouting_jumps;
    bool     unexpected_reference;
} iptables_candidate_t;

typedef struct candidate_list_s
{
    iptables_candidate_t *items;
    size_t                count;
    size_t                capacity;
} candidate_list_t;

typedef struct held_fd_list_s
{
    int   *items;
    size_t count;
    size_t capacity;
} held_fd_list_t;

static bool appendHeldFd(held_fd_list_t *list, int fd)
{
    if (fd < 0)
    {
        return true;
    }
    if (list->count == list->capacity)
    {
        const size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2U;
        int         *new_items    = memoryReAllocate(list->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL)
        {
            return false;
        }
        list->items    = new_items;
        list->capacity = new_capacity;
    }
    list->items[list->count++] = fd;
    return true;
}

static void closeHeldFds(held_fd_list_t *list)
{
    for (size_t i = 0; i < list->count; ++i)
    {
        int fd = list->items[i];
        socketManagerIptablesReleaseLease(&fd);
    }
    memoryFree(list->items);
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

static bool isUpperHex(char c)
{
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
}

static uint8_t hexValue(char c)
{
    if (c >= '0' && c <= '9')
    {
        return (uint8_t) (c - '0');
    }
    return (uint8_t) (10 + (c - 'A'));
}

bool socketManagerIptablesFormatChainName(uint64_t token, int family, char *out, size_t out_len)
{
    if (out == NULL || out_len < kSocketManagerIptablesChainNameLen + 1U || (family != 4 && family != 6))
    {
        return false;
    }
    snprintf(out, out_len, "WW2_%016" PRIX64 "_%d", token, family);
    return true;
}

bool socketManagerIptablesParseChainName(const char *name, uint64_t *token_out, int *family_out)
{
    if (name == NULL || stringLength(name) != kSocketManagerIptablesChainNameLen)
    {
        return false;
    }
    if (memcmp(name, "WW2_", 4) != 0 || name[20] != '_')
    {
        return false;
    }
    uint64_t token = 0;
    for (size_t i = 0; i < kSocketManagerIptablesTokenHexLen; ++i)
    {
        const char c = name[4 + i];
        if (! isUpperHex(c))
        {
            return false;
        }
        token = (token << 4U) | hexValue(c);
    }
    if (name[21] != '4' && name[21] != '6')
    {
        return false;
    }
    if (token_out != NULL)
    {
        *token_out = token;
    }
    if (family_out != NULL)
    {
        *family_out = name[21] == '4' ? 4 : 6;
    }
    return true;
}

void socketManagerIptablesFormatOwnerLeaseName(uint64_t token, char *out, size_t out_len)
{
    if (out == NULL || out_len == 0)
    {
        return;
    }
    snprintf(out, out_len, "waterwall.iptables.owner.v2.%016" PRIX64, token);
}

void socketManagerIptablesCleanupPlanInit(socket_manager_iptables_cleanup_plan_t *plan)
{
    assert(plan != NULL);
    plan->ops      = NULL;
    plan->count    = 0;
    plan->capacity = 0;
}

void socketManagerIptablesCleanupPlanDrop(socket_manager_iptables_cleanup_plan_t *plan)
{
    if (plan == NULL)
    {
        return;
    }
    memoryFree(plan->ops);
    plan->ops      = NULL;
    plan->count    = 0;
    plan->capacity = 0;
}

static bool appendCleanupOp(socket_manager_iptables_cleanup_plan_t *plan,
                            const iptables_candidate_t *candidate,
                            socket_manager_iptables_cleanup_action_t action)
{
    if (plan->count == plan->capacity)
    {
        const size_t new_capacity = plan->capacity == 0 ? 16 : plan->capacity * 2U;
        socket_manager_iptables_cleanup_op_t *new_ops =
            memoryReAllocate(plan->ops, new_capacity * sizeof(*new_ops));
        if (new_ops == NULL)
        {
            return false;
        }
        plan->ops      = new_ops;
        plan->capacity = new_capacity;
    }
    socket_manager_iptables_cleanup_op_t *op = &plan->ops[plan->count++];
    op->family                               = candidate->family;
    op->action                               = action;
    snprintf(op->chain_name, sizeof(op->chain_name), "%s", candidate->chain_name);
    return true;
}

static iptables_candidate_t *findCandidate(candidate_list_t *list, const char *chain_name)
{
    for (size_t i = 0; i < list->count; ++i)
    {
        if (strcmp(list->items[i].chain_name, chain_name) == 0)
        {
            return &list->items[i];
        }
    }
    return NULL;
}

static bool appendCandidate(candidate_list_t *list, uint64_t token, int family, const char *chain_name)
{
    if (findCandidate(list, chain_name) != NULL)
    {
        return true;
    }
    if (list->count == list->capacity)
    {
        const size_t new_capacity = list->capacity == 0 ? 8 : list->capacity * 2U;
        iptables_candidate_t *new_items = memoryReAllocate(list->items, new_capacity * sizeof(*new_items));
        if (new_items == NULL)
        {
            return false;
        }
        list->items    = new_items;
        list->capacity = new_capacity;
    }
    iptables_candidate_t *candidate = &list->items[list->count++];
    memoryZero(candidate, sizeof(*candidate));
    candidate->token  = token;
    candidate->family = family;
    snprintf(candidate->chain_name, sizeof(candidate->chain_name), "%s", chain_name);
    return true;
}

static void dropCandidateList(candidate_list_t *list)
{
    memoryFree(list->items);
    list->items    = NULL;
    list->count    = 0;
    list->capacity = 0;
}

static bool parseChainDeclarationLine(const char *line, size_t len, int expected_family, candidate_list_t *candidates)
{
    if (len <= 3 || memcmp(line, "-N ", 3) != 0)
    {
        return true;
    }
    char chain_name[kSocketManagerIptablesChainNameBufLen];
    if (len - 3 >= sizeof(chain_name))
    {
        return true;
    }
    memoryCopy(chain_name, line + 3, len - 3);
    chain_name[len - 3] = '\0';

    uint64_t token  = 0;
    int      family = 0;
    if (! socketManagerIptablesParseChainName(chain_name, &token, &family) || family != expected_family)
    {
        return true;
    }
    return appendCandidate(candidates, token, family, chain_name);
}

static bool snapshotHasCompleteLines(const char *snapshot)
{
    if (snapshot == NULL)
    {
        return false;
    }
    const size_t len = stringLength(snapshot);
    return len == 0 || snapshot[len - 1] == '\n';
}

static bool collectCandidateDeclarations(const char *snapshot, int expected_family, candidate_list_t *candidates,
                                         bool *internal_failure)
{
    const char *line = snapshot;
    while (*line != '\0')
    {
        const char *end = strchr(line, '\n');
        if (end == NULL)
        {
            return false;
        }
        const size_t len = (size_t) (end - line);
        if (! parseChainDeclarationLine(line, len, expected_family, candidates))
        {
            *internal_failure = true;
            return false;
        }
        line = end + 1;
    }
    return true;
}

static int tokenizeLine(char *line, char **tokens, int max_tokens)
{
    int   count = 0;
    char *p     = line;
    while (*p != '\0')
    {
        while (*p == ' ' || *p == '\t')
        {
            ++p;
        }
        if (*p == '\0')
        {
            break;
        }
        if (count >= max_tokens)
        {
            return -1;
        }
        tokens[count++] = p;
        while (*p != '\0' && *p != ' ' && *p != '\t')
        {
            ++p;
        }
        if (*p != '\0')
        {
            *p++ = '\0';
        }
    }
    return count;
}

static void markAllCandidatesUnexpected(candidate_list_t *candidates)
{
    for (size_t i = 0; i < candidates->count; ++i)
    {
        candidates->items[i].unexpected_reference = true;
    }
}

static bool analyzeRuleLine(const char *line, size_t len, candidate_list_t *candidates)
{
    if (len <= 3 || memcmp(line, "-A ", 3) != 0)
    {
        return true;
    }
    char *copy = memoryAllocate(len + 1U);
    if (copy == NULL)
    {
        return false;
    }
    memoryCopy(copy, line, len);
    copy[len] = '\0';

    char *tokens[128];
    int   count = tokenizeLine(copy, tokens, 128);
    if (count < 0)
    {
        markAllCandidatesUnexpected(candidates);
        memoryFree(copy);
        return true;
    }
    for (int i = 0; i + 1 < count; ++i)
    {
        const bool short_jump = strcmp(tokens[i], "-j") == 0;
        const bool reference  = short_jump || strcmp(tokens[i], "--jump") == 0 || strcmp(tokens[i], "-g") == 0 ||
                               strcmp(tokens[i], "--goto") == 0;
        if (! reference)
        {
            continue;
        }
        iptables_candidate_t *candidate = findCandidate(candidates, tokens[i + 1]);
        if (candidate == NULL)
        {
            continue;
        }
        const bool exact_unconditional_prerouting =
            count == 4 && strcmp(tokens[0], "-A") == 0 && strcmp(tokens[1], "PREROUTING") == 0 &&
            i == 2 && short_jump;
        if (exact_unconditional_prerouting)
        {
            ++candidate->prerouting_jumps;
        }
        else
        {
            candidate->unexpected_reference = true;
        }
    }
    memoryFree(copy);
    return true;
}

static bool analyzeReferences(const char *snapshot, candidate_list_t *candidates, bool *internal_failure)
{
    const char *line = snapshot;
    while (*line != '\0')
    {
        const char *end = strchr(line, '\n');
        if (end == NULL)
        {
            return false;
        }
        if (! analyzeRuleLine(line, (size_t) (end - line), candidates))
        {
            *internal_failure = true;
            return false;
        }
        line = end + 1;
    }
    return true;
}

static bool parseSnapshot(const char *snapshot, bool include, int family, candidate_list_t *candidates,
                          bool *internal_failure)
{
    if (! include)
    {
        return true;
    }
    if (! snapshotHasCompleteLines(snapshot))
    {
        return false;
    }
    if (! collectCandidateDeclarations(snapshot, family, candidates, internal_failure))
    {
        return false;
    }
    return analyzeReferences(snapshot, candidates, internal_failure);
}

static bool tokenWasSeen(const uint64_t *tokens, size_t count, uint64_t token)
{
    for (size_t i = 0; i < count; ++i)
    {
        if (tokens[i] == token)
        {
            return true;
        }
    }
    return false;
}

static bool appendToken(uint64_t **tokens, size_t *count, size_t *capacity, uint64_t token)
{
    if (tokenWasSeen(*tokens, *count, token))
    {
        return true;
    }
    if (*count == *capacity)
    {
        const size_t new_capacity = *capacity == 0 ? 8 : *capacity * 2U;
        uint64_t    *new_tokens   = memoryReAllocate(*tokens, new_capacity * sizeof(*new_tokens));
        if (new_tokens == NULL)
        {
            return false;
        }
        *tokens   = new_tokens;
        *capacity = new_capacity;
    }
    (*tokens)[(*count)++] = token;
    return true;
}

static bool candidateFamilyIncluded(const iptables_candidate_t *candidate, bool include_v4, bool include_v6)
{
    return (candidate->family == 4 && include_v4) || (candidate->family == 6 && include_v6);
}

static void markIncludedFamiliesFailed(bool include_v4, bool include_v6, bool *v4_ok, bool *v6_ok)
{
    if (include_v4 && v4_ok != NULL)
    {
        *v4_ok = false;
    }
    if (include_v6 && v6_ok != NULL)
    {
        *v6_ok = false;
    }
}

bool socketManagerIptablesBuildCleanupPlan(const char *snapshot_v4, bool include_v4,
                                           const char *snapshot_v6, bool include_v6,
                                           socket_manager_iptables_probe_owner_fn probe_owner,
                                           void *probe_userdata,
                                           socket_manager_iptables_cleanup_plan_t *plan,
                                           bool *v4_ok, bool *v6_ok)
{
    assert(plan != NULL);
    if (v4_ok != NULL)
    {
        *v4_ok = true;
    }
    if (v6_ok != NULL)
    {
        *v6_ok = true;
    }

    candidate_list_t candidates = {0};
    held_fd_list_t   held_fds   = {0};
    uint64_t        *tokens     = NULL;
    size_t           token_count = 0, token_capacity = 0;
    bool             result = true;
    bool             internal_failure = false;

    bool v4_internal_failure = false;
    if (! parseSnapshot(snapshot_v4, include_v4, 4, &candidates, &v4_internal_failure))
    {
        if (v4_ok != NULL)
        {
            *v4_ok = false;
        }
        result = false;
        internal_failure = v4_internal_failure;
    }
    bool v6_internal_failure = false;
    if (! parseSnapshot(snapshot_v6, include_v6, 6, &candidates, &v6_internal_failure))
    {
        if (v6_ok != NULL)
        {
            *v6_ok = false;
        }
        result = false;
        internal_failure = internal_failure || v6_internal_failure;
    }
    if (internal_failure)
    {
        goto done;
    }

    for (size_t i = 0; i < candidates.count; ++i)
    {
        if (! appendToken(&tokens, &token_count, &token_capacity, candidates.items[i].token))
        {
            internal_failure = true;
            goto done;
        }
    }

    for (size_t ti = 0; ti < token_count; ++ti)
    {
        const uint64_t token = tokens[ti];
        int            held_fd = -1;
        socket_manager_iptables_lease_probe_result_t lease =
            probe_owner != NULL ? probe_owner(token, &held_fd, probe_userdata) : kSocketManagerIptablesLeaseError;

        if (lease == kSocketManagerIptablesLeaseInUse)
        {
            continue;
        }
        if (lease == kSocketManagerIptablesLeaseError)
        {
            for (size_t ci = 0; ci < candidates.count; ++ci)
            {
                if (candidates.items[ci].token == token)
                {
                    if (candidates.items[ci].family == 4 && v4_ok != NULL)
                    {
                        *v4_ok = false;
                    }
                    if (candidates.items[ci].family == 6 && v6_ok != NULL)
                    {
                        *v6_ok = false;
                    }
                }
            }
            result = false;
            continue;
        }
        if (! appendHeldFd(&held_fds, held_fd))
        {
            socketManagerIptablesReleaseLease(&held_fd);
            internal_failure = true;
            goto done;
        }

        for (size_t ci = 0; ci < candidates.count; ++ci)
        {
            iptables_candidate_t *candidate = &candidates.items[ci];
            if (candidate->token != token || ! candidateFamilyIncluded(candidate, include_v4, include_v6))
            {
                continue;
            }
            if (candidate->unexpected_reference)
            {
                if (candidate->family == 4 && v4_ok != NULL)
                {
                    *v4_ok = false;
                }
                if (candidate->family == 6 && v6_ok != NULL)
                {
                    *v6_ok = false;
                }
                result = false;
                continue;
            }
            for (size_t jump_i = 0; jump_i < candidate->prerouting_jumps; ++jump_i)
            {
                if (! appendCleanupOp(plan, candidate, kSocketManagerIptablesCleanupDeleteJump))
                {
                    internal_failure = true;
                    goto done;
                }
            }
            if (! appendCleanupOp(plan, candidate, kSocketManagerIptablesCleanupFlushChain) ||
                ! appendCleanupOp(plan, candidate, kSocketManagerIptablesCleanupDeleteChain))
            {
                internal_failure = true;
                goto done;
            }
        }
    }

done:
    if (internal_failure)
    {
        markIncludedFamiliesFailed(include_v4, include_v6, v4_ok, v6_ok);
        socketManagerIptablesCleanupPlanDrop(plan);
        socketManagerIptablesCleanupPlanInit(plan);
        result = false;
    }
    closeHeldFds(&held_fds);
    memoryFree(tokens);
    dropCandidateList(&candidates);
    return result;
}

bool socketManagerIptablesExecuteCleanupPlan(const socket_manager_iptables_cleanup_plan_t *plan,
                                             socket_manager_iptables_run_cleanup_fn run_op,
                                             void *userdata,
                                             bool *v4_ok, bool *v6_ok)
{
    assert(plan != NULL);
    bool result = true;
    int  current_family = 0;
    char current_chain[kSocketManagerIptablesChainNameBufLen] = {0};
    bool unlink_failed = false;
    bool flush_failed  = false;
    for (size_t i = 0; i < plan->count; ++i)
    {
        const socket_manager_iptables_cleanup_op_t *op = &plan->ops[i];
        if (op->family != current_family || strcmp(op->chain_name, current_chain) != 0)
        {
            current_family = op->family;
            snprintf(current_chain, sizeof(current_chain), "%s", op->chain_name);
            unlink_failed = false;
            flush_failed  = false;
        }

        const bool prerequisite_failed =
            (op->action == kSocketManagerIptablesCleanupFlushChain && unlink_failed) ||
            (op->action == kSocketManagerIptablesCleanupDeleteChain && (unlink_failed || flush_failed));
        const bool op_failed = prerequisite_failed || run_op == NULL || ! run_op(op, userdata);
        if (! op_failed)
        {
            continue;
        }

        if (op->action == kSocketManagerIptablesCleanupDeleteJump)
        {
            unlink_failed = true;
        }
        else if (op->action == kSocketManagerIptablesCleanupFlushChain)
        {
            flush_failed = true;
        }

        if (op->family == 4 && v4_ok != NULL)
        {
            *v4_ok = false;
        }
        if (op->family == 6 && v6_ok != NULL)
        {
            *v6_ok = false;
        }
        result = false;
    }
    return result;
}

void socketManagerIptablesCmdOutputDrop(socket_manager_iptables_cmd_output_t *out)
{
    if (out == NULL)
    {
        return;
    }
    memoryFree(out->output);
    memoryZero(out, sizeof(*out));
}

#if defined(OS_LINUX)
static bool reapInspectChild(pid_t pid, bool terminate_child, socket_manager_iptables_cmd_output_t *out)
{
    if (terminate_child && kill(pid, SIGTERM) != 0 && errno != ESRCH)
    {
        out->spawn_failed = true;
    }

    int status = 0;
    while (waitpid(pid, &status, 0) < 0)
    {
        if (errno == EINTR)
        {
            continue;
        }
        out->spawn_failed = true;
        return false;
    }
    if (WIFEXITED(status))
    {
        out->exit_code = WEXITSTATUS(status);
    }
    else if (WIFSIGNALED(status))
    {
        out->exit_code = 128 + WTERMSIG(status);
    }
    return true;
}
#endif

bool socketManagerIptablesRunInspectCommand(const char *tool, socket_manager_iptables_cmd_output_t *out)
{
    assert(out != NULL);
    memoryZero(out, sizeof(*out));
    out->exit_code = -1;
#if defined(OS_LINUX)
    int output_pipe[2] = {-1, -1};
    if (pipe(output_pipe) != 0)
    {
        out->spawn_failed = true;
        return false;
    }

    pid_t pid = fork();
    if (pid < 0)
    {
        close(output_pipe[0]);
        close(output_pipe[1]);
        out->spawn_failed = true;
        return false;
    }

    if (pid == 0)
    {
        close(output_pipe[0]);
        if (output_pipe[1] != STDOUT_FILENO)
        {
            if (dup2(output_pipe[1], STDOUT_FILENO) < 0)
            {
                _exit(127);
            }
            close(output_pipe[1]);
        }
        long open_max = execCmdOpenMax();
        execCmdCloseInheritedFds(open_max);
        char arg_wait[]  = "-w";
        char arg_table[] = "-t";
        char arg_nat[]   = "nat";
        char arg_list[]  = "-S";
        char *const argv[] = {(char *) tool, arg_wait, arg_table, arg_nat, arg_list, NULL};
        execvp(tool, argv);
        _exit(127);
    }

    close(output_pipe[1]);
    output_pipe[1] = -1;
    bool terminate_child = false;
    size_t capacity = 4096;
    out->output     = memoryAllocate(capacity);
    if (out->output == NULL)
    {
        out->spawn_failed = true;
        terminate_child    = true;
        goto reap_child;
    }
    out->output[0] = '\0';

    for (;;)
    {
        char    buf[4096];
        ssize_t nread = read(output_pipe[0], buf, sizeof(buf));
        if (nread > 0)
        {
            if (out->len + (size_t) nread > kSocketManagerIptablesInspectionMaxOutput)
            {
                out->output_too_large = true;
                continue;
            }
            if (out->len + (size_t) nread + 1U > capacity)
            {
                size_t new_capacity = capacity;
                while (out->len + (size_t) nread + 1U > new_capacity)
                {
                    new_capacity *= 2U;
                }
                char *new_output = memoryReAllocate(out->output, new_capacity);
                if (new_output == NULL)
                {
                    out->spawn_failed = true;
                    terminate_child    = true;
                    goto reap_child;
                }
                out->output = new_output;
                capacity    = new_capacity;
            }
            memoryCopy(out->output + out->len, buf, (size_t) nread);
            out->len += (size_t) nread;
            out->output[out->len] = '\0';
            continue;
        }
        if (nread == 0)
        {
            break;
        }
        if (errno == EINTR)
        {
            continue;
        }
        out->spawn_failed = true;
        terminate_child    = true;
        break;
    }

reap_child:
    close(output_pipe[0]);
    output_pipe[0] = -1;
    if (! reapInspectChild(pid, terminate_child, out))
    {
        return false;
    }
    out->incomplete_final_line = out->len > 0 && out->output[out->len - 1] != '\n';
    return out->exit_code == 0 && ! out->output_too_large && ! out->incomplete_final_line && ! out->spawn_failed;
#else
    discard tool;
    out->spawn_failed = true;
    return false;
#endif
}

#if defined(OS_LINUX)
static bool bindAbstractSocketName(const char *name, int *fd_out)
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0)
    {
        return false;
    }

    struct sockaddr_un addr;
    memoryZero(&addr, sizeof(addr));
    addr.sun_family = AF_UNIX;
    addr.sun_path[0] = '\0';
    const size_t name_len = stringLength(name);
    if (name_len + 1U > sizeof(addr.sun_path))
    {
        close(fd);
        errno = ENAMETOOLONG;
        return false;
    }
    memoryCopy(addr.sun_path + 1, name, name_len);
    const socklen_t addr_len = (socklen_t) (offsetof(struct sockaddr_un, sun_path) + 1U + name_len);
    if (bind(fd, (const struct sockaddr *) &addr, addr_len) != 0)
    {
        close(fd);
        return false;
    }
    *fd_out = fd;
    return true;
}
#endif

bool socketManagerIptablesAcquireReconcileLock(int *fd_out, uint32_t timeout_ms)
{
    assert(fd_out != NULL);
    *fd_out = -1;
#if defined(OS_LINUX)
    const uint32_t sleep_ms = 50;
    uint32_t       waited   = 0;
    for (;;)
    {
        if (bindAbstractSocketName("waterwall.iptables.reconcile.v2", fd_out))
        {
            return true;
        }
        if (errno != EADDRINUSE || waited >= timeout_ms)
        {
            return false;
        }
        usleep((useconds_t) sleep_ms * 1000U);
        waited += sleep_ms;
    }
#else
    discard timeout_ms;
    return false;
#endif
}

socket_manager_iptables_lease_probe_result_t socketManagerIptablesAcquireOwnerLease(uint64_t token, int *fd_out)
{
    assert(fd_out != NULL);
    *fd_out = -1;
#if defined(OS_LINUX)
    char name[64];
    socketManagerIptablesFormatOwnerLeaseName(token, name, sizeof(name));
    if (bindAbstractSocketName(name, fd_out))
    {
        return kSocketManagerIptablesLeaseAcquired;
    }
    if (errno == EADDRINUSE)
    {
        return kSocketManagerIptablesLeaseInUse;
    }
    return kSocketManagerIptablesLeaseError;
#else
    discard token;
    return kSocketManagerIptablesLeaseError;
#endif
}

void socketManagerIptablesReleaseLease(int *fd)
{
    if (fd == NULL || *fd < 0)
    {
        return;
    }
#if defined(OS_UNIX)
    close(*fd);
#endif
    *fd = -1;
}
