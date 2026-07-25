#pragma once

#include "wlibc.h"

enum
{
    kSocketManagerIptablesTokenHexLen         = 16,
    kSocketManagerIptablesChainNameLen        = 22,
    kSocketManagerIptablesLegacyChainNameLen  = 22,
    kSocketManagerIptablesChainNameBufLen     = 32,
    kSocketManagerIptablesInspectionMaxOutput = 1024 * 1024,

    // Two independent timeout layers guard every WaterWall iptables/ip6tables
    // command. The numeric xtables lock wait (`-w 5`) only bounds lock
    // acquisition inside iptables; the parent-side command deadline is
    // authoritative and also covers a hung executable, wrapper, or shell. The
    // parent deadline must stay strictly longer than the numeric wait so a
    // normal lock timeout can exit and be reaped without racing the supervisor.
    kSocketManagerIptablesLockWaitSeconds  = 5,
    kSocketManagerIptablesCommandTimeoutMs = 7000,
    kSocketManagerIptablesTerminateGraceMs = 250
};

typedef enum socket_manager_iptables_cleanup_action_e
{
    kSocketManagerIptablesCleanupDeleteJump,
    kSocketManagerIptablesCleanupFlushChain,
    kSocketManagerIptablesCleanupDeleteChain
} socket_manager_iptables_cleanup_action_t;

typedef enum socket_manager_iptables_lease_probe_result_e
{
    kSocketManagerIptablesLeaseAcquired,
    kSocketManagerIptablesLeaseInUse,
    kSocketManagerIptablesLeaseError
} socket_manager_iptables_lease_probe_result_t;

typedef struct socket_manager_iptables_cleanup_op_s
{
    int                                      family;
    socket_manager_iptables_cleanup_action_t action;
    char                                     chain_name[kSocketManagerIptablesChainNameBufLen];
} socket_manager_iptables_cleanup_op_t;

// Diagnostic describing a still-linked chain left by an older WaterWall release.
// Legacy chains have no owner lease, so they are never mutated automatically; a
// referenced legacy chain simply blocks publication for its own address family.
typedef struct socket_manager_iptables_legacy_blocker_s
{
    int    family;
    char   chain_name[kSocketManagerIptablesChainNameBufLen];
    size_t prerouting_jumps;
    bool   unexpected_reference;
} socket_manager_iptables_legacy_blocker_t;

typedef struct socket_manager_iptables_cleanup_plan_s
{
    socket_manager_iptables_cleanup_op_t     *ops;
    size_t                                    count;
    size_t                                    capacity;
    socket_manager_iptables_legacy_blocker_t *blockers;
    size_t                                    blocker_count;
    size_t                                    blocker_capacity;
} socket_manager_iptables_cleanup_plan_t;

typedef socket_manager_iptables_lease_probe_result_t (*socket_manager_iptables_probe_owner_fn)(uint64_t token,
                                                                                               int     *held_fd,
                                                                                               void    *userdata);

typedef bool (*socket_manager_iptables_run_cleanup_fn)(const socket_manager_iptables_cleanup_op_t *op, void *userdata);

typedef struct socket_manager_iptables_cmd_output_s
{
    char  *output;
    size_t len;
    int    exit_code;
    bool   output_too_large;
    bool   incomplete_final_line;
    bool   spawn_failed;
    bool   timed_out;
} socket_manager_iptables_cmd_output_t;

bool socketManagerIptablesFormatChainName(uint64_t token, int family, char *out, size_t out_len);
bool socketManagerIptablesParseChainName(const char *name, uint64_t *token_out, int *family_out);
bool socketManagerIptablesParseLegacyChainName(const char *name, int *family_out);
void socketManagerIptablesFormatOwnerLeaseName(uint64_t token, char *out, size_t out_len);

void socketManagerIptablesCleanupPlanInit(socket_manager_iptables_cleanup_plan_t *plan);
void socketManagerIptablesCleanupPlanDrop(socket_manager_iptables_cleanup_plan_t *plan);

bool socketManagerIptablesBuildCleanupPlan(const char *snapshot_v4, bool include_v4, const char *snapshot_v6,
                                           bool include_v6, socket_manager_iptables_probe_owner_fn probe_owner,
                                           void *probe_userdata, socket_manager_iptables_cleanup_plan_t *plan,
                                           bool *v4_ok, bool *v6_ok);

bool socketManagerIptablesExecuteCleanupPlan(const socket_manager_iptables_cleanup_plan_t *plan,
                                             socket_manager_iptables_run_cleanup_fn run_op, void *userdata, bool *v4_ok,
                                             bool *v6_ok);

// Run `<tool> -w 5 -t nat -S` directly (no shell) under a parent-enforced
// deadline. `timeout_ms` is injectable so tests need not wait for the
// production deadline; production callers pass kSocketManagerIptablesCommandTimeoutMs.
bool socketManagerIptablesRunInspectCommand(const char *tool, uint32_t timeout_ms,
                                            socket_manager_iptables_cmd_output_t *out);

// Run an arbitrary command string through `/bin/sh -c` under the same
// deadline-aware supervisor. The child is placed in its own process group so a
// timeout terminates both the shell and any iptables descendant.
bool socketManagerIptablesRunShellCommand(const char *command, uint32_t timeout_ms,
                                          socket_manager_iptables_cmd_output_t *out);

void socketManagerIptablesCmdOutputDrop(socket_manager_iptables_cmd_output_t *out);

bool socketManagerIptablesAcquireReconcileLock(int *fd_out, uint32_t timeout_ms);
socket_manager_iptables_lease_probe_result_t socketManagerIptablesAcquireOwnerLease(uint64_t token, int *fd_out);
void                                         socketManagerIptablesReleaseLease(int *fd);
