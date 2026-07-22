#pragma once

#include "wlibc.h"

#include <stdint.h>

enum
{
    kSocketManagerIptablesTokenHexLen = 16,
    kSocketManagerIptablesChainNameLen = 22,
    kSocketManagerIptablesChainNameBufLen = 32,
    kSocketManagerIptablesInspectionMaxOutput = 1024 * 1024
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
    int family;
    socket_manager_iptables_cleanup_action_t action;
    char chain_name[kSocketManagerIptablesChainNameBufLen];
} socket_manager_iptables_cleanup_op_t;

typedef struct socket_manager_iptables_cleanup_plan_s
{
    socket_manager_iptables_cleanup_op_t *ops;
    size_t count;
    size_t capacity;
} socket_manager_iptables_cleanup_plan_t;

typedef socket_manager_iptables_lease_probe_result_t (*socket_manager_iptables_probe_owner_fn)(uint64_t token,
                                                                                               int *held_fd,
                                                                                               void *userdata);

typedef bool (*socket_manager_iptables_run_cleanup_fn)(const socket_manager_iptables_cleanup_op_t *op,
                                                       void *userdata);

typedef struct socket_manager_iptables_cmd_output_s
{
    char  *output;
    size_t len;
    int    exit_code;
    bool   output_too_large;
    bool   incomplete_final_line;
    bool   spawn_failed;
} socket_manager_iptables_cmd_output_t;

bool socketManagerIptablesFormatChainName(uint64_t token, int family, char *out, size_t out_len);
bool socketManagerIptablesParseChainName(const char *name, uint64_t *token_out, int *family_out);
void socketManagerIptablesFormatOwnerLeaseName(uint64_t token, char *out, size_t out_len);

void socketManagerIptablesCleanupPlanInit(socket_manager_iptables_cleanup_plan_t *plan);
void socketManagerIptablesCleanupPlanDrop(socket_manager_iptables_cleanup_plan_t *plan);

bool socketManagerIptablesBuildCleanupPlan(const char *snapshot_v4, bool include_v4,
                                           const char *snapshot_v6, bool include_v6,
                                           socket_manager_iptables_probe_owner_fn probe_owner,
                                           void *probe_userdata,
                                           socket_manager_iptables_cleanup_plan_t *plan,
                                           bool *v4_ok, bool *v6_ok);

bool socketManagerIptablesExecuteCleanupPlan(const socket_manager_iptables_cleanup_plan_t *plan,
                                             socket_manager_iptables_run_cleanup_fn run_op,
                                             void *userdata,
                                             bool *v4_ok, bool *v6_ok);

bool socketManagerIptablesRunInspectCommand(const char *tool, socket_manager_iptables_cmd_output_t *out);
void socketManagerIptablesCmdOutputDrop(socket_manager_iptables_cmd_output_t *out);

bool socketManagerIptablesAcquireReconcileLock(int *fd_out, uint32_t timeout_ms);
socket_manager_iptables_lease_probe_result_t socketManagerIptablesAcquireOwnerLease(uint64_t token, int *fd_out);
void socketManagerIptablesReleaseLease(int *fd);
