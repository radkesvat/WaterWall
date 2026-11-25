#include "kill_switch_wfp.h"

#include <assert.h>
#include <fwpmu.h>
#include <netioapi.h>
#include <rpc.h>
#include <sddl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>

/* Older MinGW SDK headers omit these WFP declarations. */
#ifndef FWPM_SESSION_FLAG_DYNAMIC
#define FWPM_SESSION_FLAG_DYNAMIC 0x00000001
#endif
#ifndef FWPM_SUBLAYER_FLAG_PERSISTENT
#define FWPM_SUBLAYER_FLAG_PERSISTENT 0x00000001
#endif
#ifndef FWPM_FILTER_FLAG_PERSISTENT
#define FWPM_FILTER_FLAG_PERSISTENT 0x00000001
#define FWPM_FILTER_FLAG_BOOTTIME   0x00000002
#endif
#ifndef FWPM_ACTRL_READ
#define FWPM_ACTRL_READ 0x00000080
#endif
#ifndef FWPM_ACTRL_ADD_LINK
#define FWPM_ACTRL_ADD_LINK 0x00000002
#endif
#ifndef FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_ADD
#define FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_ADD    0x00000001
#define FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE 0x00000002
#endif
#ifndef FWPM_TXN_READ_ONLY
#define FWPM_TXN_READ_ONLY 0x00000001
#endif
#ifndef FWPM_CALLOUT_FLAG_REGISTERED
#define FWPM_CALLOUT_FLAG_REGISTERED 0x00040000
#endif

/* Stable WFP layer and condition identifiers from fwpmu.h. Some MinGW SDKs
 * omit these identifiers entirely. */
static const GUID ale_layers[] = {
    {0xc38d57d1, 0x05a7, 0x4c33, {0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82}}, /* connect v4 */
    {0xe1cd9fe7, 0xf4b5, 0x4273, {0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50}}, /* accept v4 */
    {0x4a72393b, 0x319f, 0x44bc, {0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4}}, /* connect v6 */
    {0xa3b42c97, 0x9f04, 0x4672, {0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f}}, /* accept v6 */
};
static const GUID packet_layers[] = {
    {0x1e5c9fae, 0x8a84, 0x4135, {0xa3, 0x31, 0x95, 0x0b, 0x54, 0x22, 0x9e, 0xcd}}, /* outbound v4 */
    {0xc86fd1bf, 0x21cd, 0x497e, {0xa0, 0xbb, 0x17, 0x42, 0x5c, 0x88, 0x5c, 0x58}}, /* inbound v4 */
    {0xa3b3ab6b, 0x3564, 0x488c, {0x91, 0x17, 0xf3, 0x4e, 0x82, 0x14, 0x27, 0x63}}, /* outbound v6 */
    {0xf52032cb, 0x991c, 0x46e7, {0x97, 0x1d, 0x26, 0x01, 0x45, 0x9a, 0x91, 0xca}}, /* inbound v6 */
};
static const GUID forward_v4 = {0xa82acc24, 0x4ee1, 0x4ee1, {0xb4, 0x65, 0xfd, 0x1d, 0x25, 0xcb, 0x10, 0xa4}};
static const GUID condition_forward_interface = {
    0x1076b8a5, 0x6323, 0x4c5e, {0x98, 0x10, 0xe8, 0xd3, 0xfc, 0x9e, 0x61, 0x36}};
static const GUID condition_destination_index = {
    0x35cf6522, 0x4139, 0x45ee, {0xa0, 0xd5, 0x67, 0xb8, 0x09, 0x49, 0xd8, 0x79}};
static const GUID outbound_icmp_error_v4 = {
    0x41390100, 0x564c, 0x4b32, {0xbc, 0x1d, 0x71, 0x80, 0x48, 0x35, 0x4d, 0x7c}};
static const GUID inbound_transport_v4_discard = {
    0xac4a9833, 0xf69d, 0x4648, {0xb2, 0x61, 0x6d, 0xc8, 0x48, 0x35, 0xef, 0x39}};
static const GUID transport_v4_silent_drop = {
    0xeda08606, 0x2494, 0x4d78, {0x89, 0xbc, 0x67, 0x83, 0x7c, 0x03, 0xb9, 0x69}};
static const GUID condition_local_interface = {
    0x4cd62a49, 0x59c3, 0x4969, {0xb7, 0xf3, 0xbd, 0xa5, 0xd3, 0x28, 0x90, 0xa4}};
static const GUID condition_interface_index = {
    0x667fd755, 0xd695, 0x434a, {0x8a, 0xf5, 0xd3, 0x83, 0x5a, 0x12, 0x59, 0xbc}};
static const GUID condition_flags      = {0x632ce23b, 0x5167, 0x435c, {0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c}};
static const GUID condition_app        = {0xd78e1e87, 0x8644, 0x4ea5, {0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71}};
static const GUID condition_user       = {0xaf043a0a, 0xb34d, 0x4f86, {0x97, 0x9c, 0xc9, 0x03, 0x71, 0xaf, 0x6e, 0x66}};
static const GUID condition_protocol   = {0x3971ef2b, 0x623e, 0x4f9a, {0x8c, 0xb1, 0x6e, 0x79, 0xb8, 0x06, 0xb9, 0xa7}};
static const GUID condition_local_port = {0x0c1ba1af, 0x5765, 0x453f, {0xaf, 0x22, 0xa8, 0xf7, 0x91, 0xac, 0x77, 0x5b}};
static const GUID condition_remote_port = {
    0xc35a604d, 0xd22b, 0x4e1a, {0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b}};
static const GUID condition_remote_address = {
    0xb235ae9a, 0x1d64, 0x49b8, {0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45}};
static const GUID condition_arrival = {0x618a9b6d, 0x386b, 0x4136, {0xad, 0x6e, 0xb5, 0x15, 0x87, 0xcf, 0xb1, 0xcd}};
static const GUID condition_nexthop = {0x93ae8f5b, 0x7f6f, 0x4719, {0x98, 0xc8, 0x14, 0xe9, 0x74, 0x29, 0xef, 0x04}};

static const GUID waterwall_sublayer  = {0x853e7880, 0xf5bf, 0x4be7, {0x93, 0x97, 0x02, 0x7e, 0xa7, 0x94, 0x03, 0x95}};
static wchar_t    sublayer_name[]     = L"WaterWall kill switch";
static wchar_t    grant_record_name[] = L"WaterWall active grant IDs";
static wchar_t    interface_grant_name[]  = L"WaterWall permit selected IPv4 interface";
static wchar_t    tun_packet_grant_name[] = L"WaterWall permit IPv4 on the selected TUN";
/* Authenticated users can inspect the rule and its security descriptor. */
static const wchar_t policy_acl[] = L"O:BAG:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x20080;;;AU)";

enum
{
    kIp4Connect           = 0,
    kIp4Accept            = 1,
    kIp6Connect           = 2,
    kIp6Accept            = 3,
    kIp6Outbound          = 2,
    kAleDeny              = 0x10,
    kAleLoopback          = 0x14,
    kDhcp                 = 0x18,
    kBootDeny             = 0x20,
    kBootLoopback         = 0x24,
    kIp6PacketDeny        = 0x28,
    kIp6PacketLoopback    = 0x2a,
    kIp4IcmpErrorDeny     = 0x2c,
    kIp4IcmpErrorLoopback = 0x2d,
    kIp4TcpSilentDrop     = 0x2e,
    kIp4ForwardDeny       = 0x2f,
    kIp4BootForwardDeny   = 0x30,
    kImageGrant           = 0x40,
    kTunGrant             = 0x50,
    kImageFilterCount     = 4,
    kTunFilterCount       = 11,
    kBaseFilterCount      = 27,
    kInventoryIntervalMs  = 5000
};

typedef struct filter_spec_s
{
    UINT32                 key_offset;
    const GUID            *layer;
    wchar_t               *name;
    UINT32                 flags;
    FWP_ACTION_TYPE        action;
    UINT64                 weight;
    UINT32                 condition_count;
    FWPM_FILTER_CONDITION0 conditions[5];
    const GUID            *callout;
} filter_spec_t;

typedef struct dhcp_identity_s
{
    FWP_BYTE_BLOB *app;
    FWP_BYTE_BLOB  service;
} dhcp_identity_t;

typedef struct filter_session_s
{
    HANDLE          engine;
    HANDLE          subscription;
    ULONGLONG       next_inventory_check;
    GUID            session_key;
    dhcp_identity_t dhcp;
    UINT64          image_filters[kImageFilterCount];
    UINT64          tun_filters[kTunFilterCount];
} filter_session_t;

static GUID filterKey(UINT32 offset)
{
    GUID key = waterwall_sublayer;
    key.Data1 += offset;
    return key;
}

static DWORD makeAcl(const wchar_t *sddl, PSECURITY_DESCRIPTOR *descriptor)
{
    if (! ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, descriptor, NULL))
    {
        return GetLastError();
    }
    return ERROR_SUCCESS;
}

/* The launcher has one dynamic engine per protected run. Its WFP contexts
 * publish the exact immutable filter IDs returned by BFE in the grant transaction. */
static const GUID    empty_key = {0};
static volatile LONG filter_inventory_changed;

static void CALLBACK filtersChanged(void *unused, const FWPM_FILTER_CHANGE0 *change)
{
    (void) unused;
    (void) change;
    /* Process-lifetime storage; the callback never needs the launcher or its locks. */
    InterlockedExchange(&filter_inventory_changed, 1);
}

static DWORD openEngine(const GUID *dynamic_key, HANDLE *engine)
{
    FWPM_SESSION0 session    = {0};
    session.displayData.name = sublayer_name;
    if (dynamic_key != NULL)
    {
        session.flags      = FWPM_SESSION_FLAG_DYNAMIC;
        session.sessionKey = *dynamic_key;
    }
    session.txnWaitTimeoutInMSec = 1000;
    return FwpmEngineOpen0(NULL, RPC_C_AUTHN_WINNT, NULL, &session, engine);
}

static DWORD finishTransaction(HANDLE engine, DWORD status)
{
    if (status == ERROR_SUCCESS)
    {
        status = FwpmTransactionCommit0(engine);
    }
    if (status != ERROR_SUCCESS)
    {
        FwpmTransactionAbort0(engine);
    }
    return status;
}

static DWORD openDhcpIdentity(dhcp_identity_t *identity)
{
    wchar_t       path[MAX_PATH];
    const wchar_t system_image[] = L"\\System32\\svchost.exe";
    UINT          length         = GetSystemWindowsDirectoryW(path, ARRAYSIZE(path));
    if (length == 0)
    {
        return GetLastError();
    }
    if (length > ARRAYSIZE(path) - ARRAYSIZE(system_image))
    {
        return ERROR_INSUFFICIENT_BUFFER;
    }
    memcpy(path + length, system_image, sizeof(system_image));

    BOOL wow64 = FALSE;
    if (! IsWow64Process(GetCurrentProcess(), &wow64))
    {
        return GetLastError();
    }
    PVOID redirection = NULL;
    if (wow64 && ! Wow64DisableWow64FsRedirection(&redirection))
    {
        return GetLastError();
    }
    DWORD status = FwpmGetAppIdFromFileName0(path, &identity->app);
    if (wow64 && ! Wow64RevertWow64FsRedirection(redirection) && status == ERROR_SUCCESS)
    {
        status = GetLastError();
    }
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    /* NT SERVICE\Dhcp has the SCM name-derived service SID below. CC grants
     * the WFP match-filter right to that SID. */
    PSECURITY_DESCRIPTOR service = NULL;
    ULONG                size    = 0;
    if (! ConvertStringSecurityDescriptorToSecurityDescriptorW(
            L"D:(A;;CC;;;S-1-5-80-2940520708-3855866260-481812779-327648279-1710889582)",
            SDDL_REVISION_1,
            &service,
            &size))
    {
        return GetLastError();
    }
    identity->service.size = size;
    identity->service.data = service;
    return ERROR_SUCCESS;
}

static void closeDhcpIdentity(dhcp_identity_t *identity)
{
    FwpmFreeMemory0((void **) &identity->app);
    LocalFree(identity->service.data);
}

static filter_spec_t loopbackRule(UINT32 offset, const GUID *layer, UINT32 flags)
{
    filter_spec_t rule = {offset, layer, L"WaterWall permit loopback", flags, FWP_ACTION_PERMIT, 10, 1, {0}, NULL};
    rule.conditions[0] = (FWPM_FILTER_CONDITION0) {
        condition_flags, FWP_MATCH_FLAGS_ALL_SET, {.type = FWP_UINT32, .uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK}};
    return rule;
}

static filter_spec_t denyRule(UINT32 offset, const GUID *layer, UINT32 flags)
{
    return (filter_spec_t) {offset, layer, L"WaterWall default block", flags, FWP_ACTION_BLOCK, 0, 0, {0}, NULL};
}

static filter_spec_t dhcpRule(UINT32 offset, const GUID *layer, dhcp_identity_t *identity)
{
    filter_spec_t rule = {offset,
                          layer,
                          L"WaterWall permit DHCPv4 client",
                          FWPM_FILTER_FLAG_PERSISTENT,
                          FWP_ACTION_PERMIT,
                          10,
                          5,
                          {0},
                          NULL};
    rule.conditions[0] = (FWPM_FILTER_CONDITION0) {
        condition_app, FWP_MATCH_EQUAL, {.type = FWP_BYTE_BLOB_TYPE, .byteBlob = identity->app}};
    rule.conditions[1] = (FWPM_FILTER_CONDITION0) {
        condition_user, FWP_MATCH_EQUAL, {.type = FWP_SECURITY_DESCRIPTOR_TYPE, .sd = &identity->service}};
    rule.conditions[2] =
        (FWPM_FILTER_CONDITION0) {condition_protocol, FWP_MATCH_EQUAL, {.type = FWP_UINT8, .uint8 = IPPROTO_UDP}};
    rule.conditions[3] =
        (FWPM_FILTER_CONDITION0) {condition_local_port, FWP_MATCH_EQUAL, {.type = FWP_UINT16, .uint16 = 68}};
    rule.conditions[4] =
        (FWPM_FILTER_CONDITION0) {condition_remote_port, FWP_MATCH_EQUAL, {.type = FWP_UINT16, .uint16 = 67}};
    return rule;
}

/* Closed-port TCP responses never visit ALE. Windows' built-in discard callout
 * suppresses the reset at its source while ordinary TCP flow resets still work. */
static filter_spec_t silentDropRule(void)
{
    return (filter_spec_t) {
        .key_offset      = kIp4TcpSilentDrop,
        .layer           = &inbound_transport_v4_discard,
        .name            = L"WaterWall suppress physical closed-port TCP resets",
        .flags           = FWPM_FILTER_FLAG_PERSISTENT,
        .action          = FWP_ACTION_CALLOUT_TERMINATING,
        .condition_count = 2,
        .conditions =
            {
                {condition_flags,
                 FWP_MATCH_FLAGS_NONE_SET,
                 {.type = FWP_UINT32, .uint32 = FWP_CONDITION_FLAG_IS_LOOPBACK}},
                {condition_protocol, FWP_MATCH_EQUAL, {.type = FWP_UINT8, .uint8 = IPPROTO_TCP}},
            },
        .callout = &transport_v4_silent_drop,
    };
}

static DWORD checkSilentDropCallout(HANDLE engine, bool *registered)
{
    FWPM_CALLOUT0 *callout = NULL;
    DWORD          status  = FwpmCalloutGetByKey0(engine, &transport_v4_silent_drop, &callout);
    *registered            = status == ERROR_SUCCESS && (callout->flags & FWPM_CALLOUT_FLAG_REGISTERED) != 0 &&
                  IsEqualGUID(&callout->applicableLayer, &inbound_transport_v4_discard);
    FwpmFreeMemory0((void **) &callout);
    return status == (DWORD) FWP_E_CALLOUT_NOT_FOUND ? ERROR_SUCCESS : status;
}

static void baseRules(filter_spec_t rules[kBaseFilterCount], dhcp_identity_t *identity)
{
    size_t count = 0;
    for (UINT32 layer = 0; layer < ARRAYSIZE(ale_layers); ++layer)
    {
        rules[count++] = denyRule(kAleDeny + layer, &ale_layers[layer], FWPM_FILTER_FLAG_PERSISTENT);
        rules[count++] = loopbackRule(kAleLoopback + layer, &ale_layers[layer], FWPM_FILTER_FLAG_PERSISTENT);
    }
    rules[count++] = dhcpRule(kDhcp, &ale_layers[kIp4Connect], identity);
    rules[count++] = dhcpRule(kDhcp + 1, &ale_layers[kIp4Accept], identity);
    for (UINT32 layer = 0; layer < ARRAYSIZE(packet_layers); ++layer)
    {
        rules[count++] = denyRule(kBootDeny + layer, &packet_layers[layer], FWPM_FILTER_FLAG_BOOTTIME);
        rules[count++] = loopbackRule(kBootLoopback + layer, &packet_layers[layer], FWPM_FILTER_FLAG_BOOTTIME);
    }
    for (UINT32 direction = 0; direction < 2; ++direction)
    {
        const GUID *layer = &packet_layers[kIp6Outbound + direction];
        rules[count++]    = denyRule(kIp6PacketDeny + direction, layer, FWPM_FILTER_FLAG_PERSISTENT);
        rules[count++]    = loopbackRule(kIp6PacketLoopback + direction, layer, FWPM_FILTER_FLAG_PERSISTENT);
    }
    /* Outbound ICMP errors are indicated here irrespective of ICMP type. */
    rules[count++] = denyRule(kIp4IcmpErrorDeny, &outbound_icmp_error_v4, FWPM_FILTER_FLAG_PERSISTENT);
    rules[count++] = loopbackRule(kIp4IcmpErrorLoopback, &outbound_icmp_error_v4, FWPM_FILTER_FLAG_PERSISTENT);
    rules[count++] = silentDropRule();
    /* Transit packets have no local ALE flow. Keep them covered through BFE startup. */
    rules[count++] = denyRule(kIp4BootForwardDeny, &forward_v4, FWPM_FILTER_FLAG_BOOTTIME);
    rules[count++] = denyRule(kIp4ForwardDeny, &forward_v4, FWPM_FILTER_FLAG_PERSISTENT);
    assert(count == kBaseFilterCount);
}

static DWORD addRule(HANDLE engine, filter_spec_t *spec, PSECURITY_DESCRIPTOR acl, UINT64 *installed_id)
{
    FWPM_FILTER0 filter        = {0};
    filter.filterKey           = filterKey(spec->key_offset);
    filter.displayData.name    = spec->name;
    filter.flags               = spec->flags;
    filter.layerKey            = *spec->layer;
    filter.subLayerKey         = waterwall_sublayer;
    filter.weight.type         = FWP_UINT64;
    filter.weight.uint64       = &spec->weight;
    filter.numFilterConditions = spec->condition_count;
    filter.filterCondition     = spec->condition_count == 0 ? NULL : spec->conditions;
    filter.action.type         = spec->action;
    if (spec->callout != NULL)
        filter.action.calloutKey = *spec->callout;
    return FwpmFilterAdd0(engine, &filter, acl, installed_id);
}

static bool equalBlob(const FWP_BYTE_BLOB *actual, const FWP_BYTE_BLOB *wanted)
{
    return actual != NULL && wanted != NULL && actual->size == wanted->size &&
           memcmp(actual->data, wanted->data, wanted->size) == 0;
}

static bool equalCondition(const FWPM_FILTER_CONDITION0 *actual, const FWPM_FILTER_CONDITION0 *wanted)
{
    const FWP_CONDITION_VALUE0 *a = &actual->conditionValue;
    const FWP_CONDITION_VALUE0 *w = &wanted->conditionValue;
    if (! IsEqualGUID(&actual->fieldKey, &wanted->fieldKey) || actual->matchType != wanted->matchType ||
        a->type != w->type)
    {
        return false;
    }

    switch (w->type)
    {
    case FWP_UINT8:
        return a->uint8 == w->uint8;
    case FWP_UINT16:
        return a->uint16 == w->uint16;
    case FWP_UINT32:
        return a->uint32 == w->uint32;
    case FWP_BYTE_BLOB_TYPE:
        return equalBlob(a->byteBlob, w->byteBlob);
    case FWP_SECURITY_DESCRIPTOR_TYPE:
        return equalBlob(a->sd, w->sd);
    default:
        return false;
    }
}

static bool matchesRule(const FWPM_FILTER0 *filter, const filter_spec_t *spec)
{
    if (filter->providerKey != NULL || ! IsEqualGUID(&filter->layerKey, spec->layer) || filter->flags != spec->flags ||
        filter->action.type != spec->action || filter->rawContext != 0 ||
        (spec->callout != NULL && ! IsEqualGUID(&filter->action.calloutKey, spec->callout)) ||
        filter->numFilterConditions != spec->condition_count || filter->weight.type != FWP_UINT64 ||
        (spec->condition_count != 0 && filter->filterCondition == NULL) || filter->weight.uint64 == NULL ||
        *filter->weight.uint64 != spec->weight)
    {
        return false;
    }
    /* At run time boot-time objects describe the next boot policy. They need
     * not have an effective run-time weight. */
    if ((spec->flags & FWPM_FILTER_FLAG_BOOTTIME) == 0 &&
        (filter->filterId == 0 || filter->effectiveWeight.type != FWP_UINT64 ||
         filter->effectiveWeight.uint64 == NULL || *filter->effectiveWeight.uint64 != spec->weight))
    {
        return false;
    }

    for (UINT32 i = 0; i < spec->condition_count; ++i)
    {
        bool found = false;
        for (UINT32 j = 0; j < spec->condition_count; ++j)
        {
            if (equalCondition(&filter->filterCondition[j], &spec->conditions[i]))
            {
                found = true;
                break;
            }
        }
        if (! found)
        {
            return false;
        }
    }
    return true;
}

static bool trustedPrincipal(PSID sid)
{
    return sid != NULL && (IsWellKnownSid(sid, WinBuiltinAdministratorsSid) || IsWellKnownSid(sid, WinLocalSystemSid));
}

static bool safePolicyAcl(PSID owner, PACL acl)
{
    if (! trustedPrincipal(owner) || acl == NULL || ! IsValidAcl(acl))
        return false;
    const ACCESS_MASK manage         = DELETE | READ_CONTROL | WRITE_DAC | FWPM_ACTRL_READ | FWPM_ACTRL_ADD_LINK;
    ACCESS_MASK       administrators = 0, system = 0;
    for (WORD i = 0; i < acl->AceCount; ++i)
    {
        ACE_HEADER *ace = NULL;
        if (! GetAce(acl, i, (void **) &ace) || ace->AceType != ACCESS_ALLOWED_ACE_TYPE)
            return false;
        const ACCESS_ALLOWED_ACE *allow = (const ACCESS_ALLOWED_ACE *) ace;
        if ((ace->AceFlags & INHERIT_ONLY_ACE) != 0)
            continue;
        PSID sid = (PSID) &allow->SidStart;
        if (IsWellKnownSid(sid, WinBuiltinAdministratorsSid))
            administrators |= (allow->Mask & GENERIC_ALL) != 0 ? manage : allow->Mask;
        else if (IsWellKnownSid(sid, WinLocalSystemSid))
            system |= (allow->Mask & GENERIC_ALL) != 0 ? manage : allow->Mask;
        else if ((allow->Mask & ~(READ_CONTROL | FWPM_ACTRL_READ)) != 0)
            return false;
    }
    return (administrators & system & manage) == manage;
}

typedef DWORD(WINAPI *get_policy_security_fn)(HANDLE, const GUID *, SECURITY_INFORMATION, PSID *, PSID *, PACL *,
                                              PACL *, PSECURITY_DESCRIPTOR *);

static DWORD checkPolicyAcl(HANDLE engine, const GUID *key, get_policy_security_fn get_security, bool *valid)
{
    PSID                 owner      = NULL;
    PACL                 acl        = NULL;
    PSECURITY_DESCRIPTOR descriptor = NULL;
    SECURITY_INFORMATION info       = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
    DWORD                status     = get_security(engine, key, info, &owner, NULL, &acl, NULL, &descriptor);
    *valid                          = status == ERROR_SUCCESS && safePolicyAcl(owner, acl);
    FwpmFreeMemory0((void **) &descriptor);
    return status;
}

static bool ownedSublayer(const FWPM_SUBLAYER0 *sublayer)
{
    return sublayer->providerKey == NULL && sublayer->providerData.size == 0 && sublayer->displayData.name != NULL &&
           wcscmp(sublayer->displayData.name, sublayer_name) == 0;
}

static DWORD querySublayer(HANDLE engine, bool *present, bool *valid)
{
    FWPM_SUBLAYER0 *sublayer = NULL;
    DWORD           status   = FwpmSubLayerGetByKey0(engine, &waterwall_sublayer, &sublayer);
    *present                 = status == ERROR_SUCCESS;
    *valid = *present && ownedSublayer(sublayer) && sublayer->flags == FWPM_SUBLAYER_FLAG_PERSISTENT &&
             sublayer->weight == UINT16_MAX;
    FwpmFreeMemory0((void **) &sublayer);
    if (*valid)
        status = checkPolicyAcl(engine, &waterwall_sublayer, FwpmSubLayerGetSecurityInfoByKey0, valid);
    return status == (DWORD) FWP_E_SUBLAYER_NOT_FOUND ? ERROR_SUCCESS : status;
}

typedef struct grant_ids_s
{
    GUID   session;
    UINT64 image[kImageFilterCount];
    UINT64 tun[kTunFilterCount];
} grant_ids_t;

static bool issuedGrant(const FWPM_FILTER0 *filter, UINT32 offset, UINT64 id)
{
    const wchar_t *name = offset >= kTunGrant + 8 ? tun_packet_grant_name : interface_grant_name;
    return id != 0 && filter->filterId == id && filter->flags == 0 && filter->providerKey == NULL &&
           filter->providerData.size == 0 && IsEqualGUID(&filter->subLayerKey, &waterwall_sublayer) &&
           filter->action.type == FWP_ACTION_PERMIT && filter->displayData.name != NULL &&
           wcscmp(filter->displayData.name, name) == 0;
}

static bool knownFilter(const FWPM_FILTER0 *filter, const filter_spec_t *base, const grant_ids_t *grants)
{
    if (! IsEqualGUID(&filter->subLayerKey, &waterwall_sublayer))
        return true;
    UINT32 offset = filter->filterKey.Data1 - waterwall_sublayer.Data1;
    GUID   key    = filterKey(offset);
    if (! IsEqualGUID(&key, &filter->filterKey))
        return false;
    for (size_t i = 0; i < kBaseFilterCount; ++i)
        if (base[i].key_offset == offset)
            return true; /* Its full definition is separately checked by key. */
    if (offset >= kImageGrant && offset - kImageGrant < kImageFilterCount)
        return issuedGrant(filter, offset, grants->image[offset - kImageGrant]);
    if (offset >= kTunGrant && offset - kTunGrant < kTunFilterCount)
        return issuedGrant(filter, offset, grants->tun[offset - kTunGrant]);
    return false;
}

static DWORD inspectLayerFilters(HANDLE engine, const GUID *layer, const filter_spec_t *base, const grant_ids_t *grants,
                                 bool *valid)
{
    FWPM_FILTER_ENUM_TEMPLATE0 template = {0};
    template.layerKey                   = *layer;
    template.enumType                   = FWP_FILTER_ENUM_FULLY_CONTAINED;
    template.flags                      = FWP_FILTER_ENUM_FLAG_INCLUDE_BOOTTIME | FWP_FILTER_ENUM_FLAG_INCLUDE_DISABLED;
    template.actionMask                 = UINT32_MAX;
    HANDLE enumerator                   = NULL;
    DWORD  status                       = FwpmFilterCreateEnumHandle0(engine, &template, &enumerator);
    if (status != ERROR_SUCCESS)
        return status;
    UINT32 count;
    do
    {
        FWPM_FILTER0 **filters = NULL;
        count                  = 0;
        status                 = FwpmFilterEnum0(engine, enumerator, 128, &filters, &count);
        for (UINT32 i = 0; status == ERROR_SUCCESS && i < count && *valid; ++i)
            *valid = knownFilter(filters[i], base, grants);
        FwpmFreeMemory0((void **) &filters);
    } while (status == ERROR_SUCCESS && *valid && count == 128);
    DWORD closed = FwpmFilterDestroyEnumHandle0(engine, enumerator);
    return status == ERROR_SUCCESS ? closed : status;
}

/* Filter enumeration templates require a layer and have no sublayer field.
 * Enumerate across layers, including boot/disabled rules, in the caller's
 * transaction. Subscription notifications avoid rescanning other providers
 * on every 250 ms health check. */
static DWORD inspectInventory(HANDLE engine, const filter_spec_t *base, const grant_ids_t *grants, bool *valid)
{
    HANDLE enumerator = NULL;
    DWORD  status     = FwpmLayerCreateEnumHandle0(engine, NULL, &enumerator);
    if (status != ERROR_SUCCESS)
        return status;
    UINT32 count;
    do
    {
        FWPM_LAYER0 **layers = NULL;
        count                = 0;
        status               = FwpmLayerEnum0(engine, enumerator, 128, &layers, &count);
        for (UINT32 i = 0; status == ERROR_SUCCESS && i < count && *valid; ++i)
            status = inspectLayerFilters(engine, &layers[i]->layerKey, base, grants, valid);
        FwpmFreeMemory0((void **) &layers);
    } while (status == ERROR_SUCCESS && *valid && count == 128);
    DWORD closed = FwpmLayerDestroyEnumHandle0(engine, enumerator);
    return status == ERROR_SUCCESS ? closed : status;
}

static bool decodeGrantIds(const FWPM_PROVIDER_CONTEXT0 *record, UINT64 *ids, UINT32 count, GUID *session_key)
{
    if (record->providerKey != NULL || record->flags != 0 || record->type != FWPM_GENERAL_CONTEXT ||
        record->displayData.name == NULL || wcscmp(record->displayData.name, grant_record_name) != 0 ||
        record->providerData.size != sizeof(GUID) || record->providerData.data == NULL || record->dataBuffer == NULL ||
        record->dataBuffer->size != count * sizeof(*ids) || record->dataBuffer->data == NULL)
        return false;

    GUID key_from_record;
    memcpy(&key_from_record, record->providerData.data, sizeof(key_from_record));
    if (IsEqualGUID(&key_from_record, &empty_key) ||
        (! IsEqualGUID(session_key, &empty_key) && ! IsEqualGUID(session_key, &key_from_record)))
        return false;

    memcpy(ids, record->dataBuffer->data, count * sizeof(*ids));
    for (UINT32 i = 0; i < count; ++i)
        if (ids[i] == 0)
            return false;
    *session_key = key_from_record;
    return true;
}

static DWORD readGrantIds(HANDLE engine, UINT32 offset, UINT64 *ids, UINT32 count, GUID *session_key, bool *valid)
{
    const GUID              key    = filterKey(offset);
    FWPM_PROVIDER_CONTEXT0 *record = NULL;
    DWORD                   status = FwpmProviderContextGetByKey0(engine, &key, &record);
    if (status == (DWORD) FWP_E_PROVIDER_CONTEXT_NOT_FOUND)
        return ERROR_SUCCESS; /* Caller initialized this absent group to zero. */
    if (status == ERROR_SUCCESS)
    {
        *valid = decodeGrantIds(record, ids, count, session_key);
        if (*valid)
            status = checkPolicyAcl(engine, &key, FwpmProviderContextGetSecurityInfoByKey0, valid);
    }
    FwpmFreeMemory0((void **) &record);
    return status;
}

static DWORD enumerateLiveGrantSession(HANDLE engine, const GUID *session_key, bool *valid)
{
    HANDLE enumerator = NULL;
    DWORD  status     = FwpmSessionCreateEnumHandle0(engine, NULL, &enumerator);
    if (status != ERROR_SUCCESS)
        return status;
    UINT32 count;
    *valid = false;
    do
    {
        FWPM_SESSION0 **sessions = NULL;
        count                    = 0;
        status                   = FwpmSessionEnum0(engine, enumerator, 64, &sessions, &count);
        for (UINT32 i = 0; status == ERROR_SUCCESS && i < count && ! *valid; ++i)
            *valid = IsEqualGUID(&sessions[i]->sessionKey, session_key) &&
                     (sessions[i]->flags & FWPM_SESSION_FLAG_DYNAMIC) != 0 && ! sessions[i]->kernelMode &&
                     sessions[i]->displayData.name != NULL && wcscmp(sessions[i]->displayData.name, sublayer_name) == 0;
        FwpmFreeMemory0((void **) &sessions);
    } while (status == ERROR_SUCCESS && ! *valid && count == 64);
    DWORD closed = FwpmSessionDestroyEnumHandle0(engine, enumerator);
    return status == ERROR_SUCCESS ? closed : status;
}

static DWORD checkLiveGrantSession(const GUID *key, bool *valid)
{
    /* BFE session enumeration requires a nontransactional handle. Keep the
     * policy transaction open on the caller's separate engine while checking. */
    HANDLE engine = NULL;
    DWORD  status = openEngine(NULL, &engine);
    if (status != ERROR_SUCCESS)
        return status;
    status       = enumerateLiveGrantSession(engine, key, valid);
    DWORD closed = FwpmEngineClose0(engine);
    return status == ERROR_SUCCESS ? closed : status;
}

static DWORD checkGrantIds(HANDLE engine, UINT32 first, const UINT64 *ids, UINT32 count, bool inventory, bool *valid)
{
    for (UINT32 i = 0; i < count && ids[i] != 0 && *valid; ++i)
    {
        GUID          key    = filterKey(first + i);
        FWPM_FILTER0 *filter = NULL;
        DWORD         status = FwpmFilterGetByKey0(engine, &key, &filter);
        if (status != ERROR_SUCCESS && status != (DWORD) FWP_E_FILTER_NOT_FOUND)
            return status;
        /* WFP assigns a new ID when replacing an immutable filter, even if
         * the replacement uses the same key. */
        *valid = status == ERROR_SUCCESS && issuedGrant(filter, first + i, ids[i]);
        FwpmFreeMemory0((void **) &filter);
        if (*valid && inventory)
        {
            status = checkPolicyAcl(engine, &key, FwpmFilterGetSecurityInfoByKey0, valid);
            if (status != ERROR_SUCCESS)
                return status;
        }
    }
    return ERROR_SUCCESS;
}

/* The key lookup supplies the stable GUID. A foreign object can occupy that
 * key, so also require the product sublayer, name and absence of a provider. */
static bool ownedBaseFilter(const FWPM_FILTER0 *filter, const filter_spec_t *rule)
{
    return filter->providerKey == NULL && filter->providerData.size == 0 &&
           IsEqualGUID(&filter->subLayerKey, &waterwall_sublayer) && filter->displayData.name != NULL &&
           wcscmp(filter->displayData.name, rule->name) == 0;
}

static DWORD inspectBaseRule(HANDLE engine, filter_spec_t *rule, PSECURITY_DESCRIPTOR arm_acl, bool inventory,
                             bool wait_for_grants, bool *valid)
{
    const GUID    key    = filterKey(rule->key_offset);
    FWPM_FILTER0 *filter = NULL;
    DWORD         status = FwpmFilterGetByKey0(engine, &key, &filter);
    if (status == (DWORD) FWP_E_FILTER_NOT_FOUND)
    {
        *valid = arm_acl != NULL;
        return *valid && ! wait_for_grants ? addRule(engine, rule, arm_acl, NULL) : ERROR_SUCCESS;
    }
    if (status != ERROR_SUCCESS)
        return status;

    *valid       = ownedBaseFilter(filter, rule);
    bool matches = *valid && matchesRule(filter, rule);
    FwpmFreeMemory0((void **) &filter);
    if (*valid && inventory)
        status = checkPolicyAcl(engine, &key, FwpmFilterGetSecurityInfoByKey0, valid);
    if (status != ERROR_SUCCESS || ! *valid || matches)
        return status;

    *valid = arm_acl != NULL;
    if (*valid && ! wait_for_grants)
    {
        status = FwpmFilterDeleteByKey0(engine, &key);
        if (status == ERROR_SUCCESS)
            status = addRule(engine, rule, arm_acl, NULL);
    }
    return status;
}

static DWORD inspectBaseRules(HANDLE engine, filter_spec_t *rules, size_t count, PSECURITY_DESCRIPTOR arm_acl,
                              bool inventory, bool wait_for_grants, bool *valid)
{
    DWORD status = ERROR_SUCCESS;
    for (size_t i = 0; status == ERROR_SUCCESS && *valid && i < count; ++i)
        status = inspectBaseRule(engine, &rules[i], arm_acl, inventory, wait_for_grants, valid);
    return status == ERROR_SUCCESS && *valid && wait_for_grants ? ERROR_RETRY : status;
}

static DWORD inspectRules(HANDLE engine, dhcp_identity_t *identity, PSECURITY_DESCRIPTOR arm_acl,
                          const grant_ids_t *expected, bool inventory, bool *present, bool *valid)
{
    DWORD status = querySublayer(engine, present, valid);
    if (status != ERROR_SUCCESS)
        return status;
    if (! *present && arm_acl != NULL)
    {
        FWPM_SUBLAYER0 sublayer   = {0};
        sublayer.subLayerKey      = waterwall_sublayer;
        sublayer.displayData.name = sublayer_name;
        sublayer.flags            = FWPM_SUBLAYER_FLAG_PERSISTENT;
        sublayer.weight           = UINT16_MAX;
        status                    = FwpmSubLayerAdd0(engine, &sublayer, arm_acl);
        if (status != ERROR_SUCCESS)
            return status;
        *present = *valid = true;
    }
    if (! *valid)
        return ERROR_SUCCESS;

    if (identity->app == NULL)
    {
        status = openDhcpIdentity(identity);
        if (status != ERROR_SUCCESS)
            return status;
    }
    status             = checkSilentDropCallout(engine, valid);
    grant_ids_t grants = {0};
    if (status == ERROR_SUCCESS && *valid)
        status = readGrantIds(engine, kImageGrant, grants.image, ARRAYSIZE(grants.image), &grants.session, valid);
    if (status == ERROR_SUCCESS && *valid)
        status = readGrantIds(engine, kTunGrant, grants.tun, ARRAYSIZE(grants.tun), &grants.session, valid);
    bool wait_for_grants = arm_acl != NULL && grants.image[0] != 0;
    if (status == ERROR_SUCCESS && *valid)
    {
        *valid = ! (grants.tun[0] != 0 && grants.image[0] == 0) &&
                 (expected == NULL || wait_for_grants || memcmp(&grants, expected, sizeof(grants)) == 0);
        /* Status checks liveness. During arming we may see the catalog before
         * BFE completes RPC rundown. Safe grant records, exact filter IDs and
         * a clean inventory earn a retry, never admission. Session enumeration
         * on a second engine must not compete with our write transaction. */
        if (*valid && expected == NULL && grants.image[0] != 0)
            status = checkLiveGrantSession(&grants.session, valid);
    }
    if (status == ERROR_SUCCESS && *valid)
        status = checkGrantIds(engine, kImageGrant, grants.image, ARRAYSIZE(grants.image), inventory, valid);
    if (status == ERROR_SUCCESS && *valid)
        status = checkGrantIds(engine, kTunGrant, grants.tun, ARRAYSIZE(grants.tun), inventory, valid);

    filter_spec_t rules[kBaseFilterCount];
    baseRules(rules, identity);
    if (status == ERROR_SUCCESS && *valid && inventory)
        status = inspectInventory(engine, rules, &grants, valid);
    if (status == ERROR_SUCCESS && *valid)
        status = inspectBaseRules(engine, rules, ARRAYSIZE(rules), arm_acl, inventory, wait_for_grants, valid);
    return status;
}

static DWORD verifyBase(HANDLE engine, dhcp_identity_t *identity, const grant_ids_t *expected, bool *present,
                        bool *valid)
{
    DWORD status = FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY);
    if (status == ERROR_SUCCESS)
    {
        status = inspectRules(engine, identity, NULL, expected, true, present, valid);
        status = finishTransaction(engine, status);
    }
    return status;
}

DWORD launcherKillSwitchQuery(bool *locked, bool *active)
{
    *locked = *active = false;
    HANDLE engine     = NULL;
    DWORD  status     = openEngine(NULL, &engine);
    if (status == ERROR_SUCCESS)
    {
        dhcp_identity_t identity = {0};
        status                   = verifyBase(engine, &identity, NULL, locked, active);
        closeDhcpIdentity(&identity);
        FwpmEngineClose0(engine);
    }
    return status;
}

DWORD launcherKillSwitchArm(void)
{
    HANDLE engine = NULL;
    DWORD  status = openEngine(NULL, &engine);
    if (status != ERROR_SUCCESS)
    {
        return status;
    }

    dhcp_identity_t      identity = {0};
    PSECURITY_DESCRIPTOR acl      = NULL;
    status                        = openDhcpIdentity(&identity);
    if (status == ERROR_SUCCESS)
    {
        status = makeAcl(policy_acl, &acl);
    }
    if (status == ERROR_SUCCESS)
    {
        status = FwpmTransactionBegin0(engine, 0);
    }
    bool present = false;
    bool valid   = false;
    if (status == ERROR_SUCCESS)
    {
        const grant_ids_t idle = {0};
        status                 = inspectRules(engine, &identity, acl, &idle, true, &present, &valid);
        if (status == ERROR_SUCCESS && ! valid)
            status = ERROR_INVALID_DATA;
        status = finishTransaction(engine, status);
    }
    if (status == ERROR_SUCCESS)
    {
        const grant_ids_t idle = {0};
        status                 = verifyBase(engine, &identity, &idle, &present, &valid);
        if (status == ERROR_SUCCESS && (! present || ! valid))
        {
            status = ERROR_INVALID_DATA;
        }
    }
    LocalFree(acl);
    closeDhcpIdentity(&identity);
    FwpmEngineClose0(engine);
    return status;
}

static DWORD deleteOwnedRule(HANDLE engine, const filter_spec_t *rule)
{
    const GUID    key    = filterKey(rule->key_offset);
    FWPM_FILTER0 *filter = NULL;
    DWORD         status = FwpmFilterGetByKey0(engine, &key, &filter);
    if (status != ERROR_SUCCESS)
    {
        return status == (DWORD) FWP_E_FILTER_NOT_FOUND ? ERROR_SUCCESS : status;
    }
    bool owned = ownedBaseFilter(filter, rule);
    FwpmFreeMemory0((void **) &filter);
    return owned ? FwpmFilterDeleteByKey0(engine, &key) : ERROR_SUCCESS;
}

static DWORD unlockRules(HANDLE engine, bool *sublayer_retained)
{
    FWPM_SUBLAYER0 *sublayer = NULL;
    DWORD           status   = FwpmSubLayerGetByKey0(engine, &waterwall_sublayer, &sublayer);
    if (status == (DWORD) FWP_E_SUBLAYER_NOT_FOUND)
        return ERROR_SUCCESS;
    if (status != ERROR_SUCCESS)
        return status;
    bool owned = ownedSublayer(sublayer);
    FwpmFreeMemory0((void **) &sublayer);
    if (! owned)
    {
        *sublayer_retained = true;
        return ERROR_SUCCESS;
    }
    /* This table only supplies the keys. Unlock needs no DHCP identity. */
    filter_spec_t   rules[kBaseFilterCount];
    dhcp_identity_t unused = {0};
    baseRules(rules, &unused);
    for (UINT32 i = 0; i < ARRAYSIZE(rules); ++i)
    {
        status = deleteOwnedRule(engine, &rules[i]);
        if (status != ERROR_SUCCESS)
        {
            return status;
        }
    }
    status = FwpmSubLayerDeleteByKey0(engine, &waterwall_sublayer);
    if (status == (DWORD) FWP_E_IN_USE)
    {
        /* A foreign filter still references this sublayer. BFE can commit
         * the successful filter deletions in the same transaction. */
        *sublayer_retained = true;
        return ERROR_SUCCESS;
    }
    return status == (DWORD) FWP_E_SUBLAYER_NOT_FOUND ? ERROR_SUCCESS : status;
}

DWORD launcherKillSwitchUnlock(bool *sublayer_retained)
{
    *sublayer_retained = false;
    HANDLE engine      = NULL;
    DWORD  status      = openEngine(NULL, &engine);
    if (status == ERROR_SUCCESS)
    {
        status = FwpmTransactionBegin0(engine, 0);
        if (status == ERROR_SUCCESS)
        {
            status = finishTransaction(engine, unlockRules(engine, sublayer_retained));
        }
        FwpmEngineClose0(engine);
    }
    return status;
}

DWORD launcherKillSwitchOpenSession(HANDLE *session)
{
    *session                  = NULL;
    filter_session_t *created = calloc(1, sizeof(*created));
    if (created == NULL)
    {
        return ERROR_OUTOFMEMORY;
    }
    DWORD status = UuidCreate(&created->session_key);
    if (status == RPC_S_OK || status == RPC_S_UUID_LOCAL_ONLY)
        status = openEngine(&created->session_key, &created->engine);
    if (status == ERROR_SUCCESS)
    {
        status = openDhcpIdentity(&created->dhcp);
    }
    if (status == ERROR_SUCCESS)
    {
        FWPM_FILTER_SUBSCRIPTION0 subscription = {0};
        subscription.sessionKey                = created->session_key;
        subscription.flags = FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_ADD | FWPM_SUBSCRIPTION_FLAG_NOTIFY_ON_DELETE;
        status =
            FwpmFilterSubscribeChanges0(created->engine, &subscription, filtersChanged, NULL, &created->subscription);
        InterlockedExchange(&filter_inventory_changed, 1);
    }
    if (status != ERROR_SUCCESS)
    {
        launcherKillSwitchCloseSession(created);
        return status;
    }
    *session = created;
    return ERROR_SUCCESS;
}

static DWORD installGrants(filter_session_t *session, filter_spec_t *rules, UINT32 count, UINT64 *ids)
{
    PSECURITY_DESCRIPTOR acl    = NULL;
    DWORD                status = makeAcl(policy_acl, &acl);
    if (status == ERROR_SUCCESS)
    {
        status = FwpmTransactionBegin0(session->engine, 0);
    }
    if (status == ERROR_SUCCESS)
    {
        for (UINT32 i = 0; i < count && status == ERROR_SUCCESS; ++i)
        {
            status = addRule(session->engine, &rules[i], acl, &ids[i]);
        }
        if (status == ERROR_SUCCESS)
        {
            FWP_BYTE_BLOB          data   = {(UINT32) (count * sizeof(*ids)), (UINT8 *) ids};
            FWPM_PROVIDER_CONTEXT0 record = {0};
            record.providerContextKey     = filterKey(rules[0].key_offset);
            record.displayData.name       = grant_record_name;
            record.type                   = FWPM_GENERAL_CONTEXT;
            record.providerData           = (FWP_BYTE_BLOB) {sizeof(GUID), (UINT8 *) &session->session_key};
            record.dataBuffer             = &data;
            status                        = FwpmProviderContextAdd0(session->engine, &record, acl, NULL);
        }
        status = finishTransaction(session->engine, status);
        if (status != ERROR_SUCCESS)
        {
            memset(ids, 0, count * sizeof(*ids));
        }
        else
            InterlockedExchange(&filter_inventory_changed, 1);
    }
    LocalFree(acl);
    return status;
}

static filter_spec_t interfaceGrant(UINT32 offset, UINT32 layer, const GUID *interface_condition, UINT64 *luid,
                                    FWP_BYTE_BLOB *app, bool reauthorize)
{
    filter_spec_t rule = {offset, &ale_layers[layer], interface_grant_name, 0, FWP_ACTION_PERMIT, 10, 1, {0}, NULL};
    rule.conditions[0] =
        (FWPM_FILTER_CONDITION0) {*interface_condition, FWP_MATCH_EQUAL, {.type = FWP_UINT64, .uint64 = luid}};
    if (app != NULL)
    {
        rule.conditions[rule.condition_count++] =
            (FWPM_FILTER_CONDITION0) {condition_app, FWP_MATCH_EQUAL, {.type = FWP_BYTE_BLOB_TYPE, .byteBlob = app}};
    }
    if (reauthorize)
    {
        rule.conditions[rule.condition_count++] =
            (FWPM_FILTER_CONDITION0) {condition_flags,
                                      FWP_MATCH_FLAGS_ALL_SET,
                                      {.type = FWP_UINT32, .uint32 = FWP_CONDITION_FLAG_IS_REAUTHORIZE}};
    }
    if (layer == kIp6Connect || layer == kIp6Accept)
    {
        /* Dual-stack sockets can report genuine IPv4 peers at the IPv6 ALE
         * layers. The IPv6 packet-layer deny still applies to native IPv6. */
        static FWP_V6_ADDR_AND_MASK mapped      = {{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 0, 0}, 96};
        rule.conditions[rule.condition_count++] = (FWPM_FILTER_CONDITION0) {
            condition_remote_address, FWP_MATCH_EQUAL, {.type = FWP_V6_ADDR_MASK, .v6AddrMask = &mapped}};
    }
    return rule;
}

DWORD launcherKillSwitchGrantImage(HANDLE session_handle, const wchar_t *image, NET_LUID uplink)
{
    filter_session_t *session = session_handle;
    if (uplink.Value == 0 || session->image_filters[0] != 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    FWP_BYTE_BLOB *app    = NULL;
    DWORD          status = FwpmGetAppIdFromFileName0(image, &app);
    if (status == ERROR_SUCCESS)
    {
        /* All four filters authorize outbound flows at CONNECT. The arrival
         * matches cover replies reauthorized at that same layer. */
        filter_spec_t rules[kImageFilterCount] = {
            interfaceGrant(kImageGrant, kIp4Connect, &condition_nexthop, &uplink.Value, app, false),
            interfaceGrant(kImageGrant + 1, kIp4Connect, &condition_arrival, &uplink.Value, app, true),
            interfaceGrant(kImageGrant + 2, kIp6Connect, &condition_nexthop, &uplink.Value, app, false),
            interfaceGrant(kImageGrant + 3, kIp6Connect, &condition_arrival, &uplink.Value, app, true),
        };
        status = installGrants(session, rules, ARRAYSIZE(rules), session->image_filters);
    }
    FwpmFreeMemory0((void **) &app);
    return status;
}

static filter_spec_t tunPacketGrant(UINT32 offset, const GUID *layer, const GUID *luid_field, UINT64 *luid,
                                    const GUID *index_field, NET_IFINDEX index)
{
    return (filter_spec_t) {
        .key_offset      = offset,
        .layer           = layer,
        .name            = tun_packet_grant_name,
        .action          = FWP_ACTION_PERMIT,
        .weight          = 10,
        .condition_count = 2,
        .conditions =
            {
                {*luid_field, FWP_MATCH_EQUAL, {.type = FWP_UINT64, .uint64 = luid}},
                {*index_field, FWP_MATCH_EQUAL, {.type = FWP_UINT32, .uint32 = index}},
            },
    };
}

static void tunRules(filter_spec_t rules[kTunFilterCount], UINT64 *luid, NET_IFINDEX index)
{
    rules[0] = interfaceGrant(kTunGrant, kIp4Connect, &condition_nexthop, luid, NULL, false);
    rules[1] = interfaceGrant(kTunGrant + 1, kIp4Connect, &condition_arrival, luid, NULL, true);
    rules[2] = interfaceGrant(kTunGrant + 2, kIp4Accept, &condition_arrival, luid, NULL, false);
    rules[3] = interfaceGrant(kTunGrant + 3, kIp4Accept, &condition_nexthop, luid, NULL, true);
    rules[4] = interfaceGrant(kTunGrant + 4, kIp6Connect, &condition_nexthop, luid, NULL, false);
    rules[5] = interfaceGrant(kTunGrant + 5, kIp6Connect, &condition_arrival, luid, NULL, true);
    rules[6] = interfaceGrant(kTunGrant + 6, kIp6Accept, &condition_arrival, luid, NULL, false);
    rules[7] = interfaceGrant(kTunGrant + 7, kIp6Accept, &condition_nexthop, luid, NULL, true);
    rules[8] = tunPacketGrant(
        kTunGrant + 8, &outbound_icmp_error_v4, &condition_local_interface, luid, &condition_interface_index, index);
    rules[9] = tunPacketGrant(kTunGrant + 9,
                              &inbound_transport_v4_discard,
                              &condition_local_interface,
                              luid,
                              &condition_interface_index,
                              index);
    /* Bind forwarding to the outgoing Wintun interface. A packet arriving
     * from Wintun must still satisfy the block on forwarding to another link. */
    rules[10] = tunPacketGrant(
        kTunGrant + 10, &forward_v4, &condition_forward_interface, luid, &condition_destination_index, index);
}

DWORD launcherKillSwitchGrantTun(HANDLE session_handle, NET_LUID tun)
{
    filter_session_t *session = session_handle;
    if (tun.Value == 0 || session->image_filters[0] == 0 || session->tun_filters[0] != 0)
    {
        return ERROR_INVALID_PARAMETER;
    }

    NET_IFINDEX index;
    DWORD       status = ConvertInterfaceLuidToIndex(&tun, &index);
    if (status != ERROR_SUCCESS || index == 0)
        return status == ERROR_SUCCESS ? ERROR_INVALID_DATA : status;

    filter_spec_t rules[kTunFilterCount];
    tunRules(rules, &tun.Value, index);
    return installGrants(session, rules, ARRAYSIZE(rules), session->tun_filters);
}

DWORD launcherKillSwitchRevokeTun(HANDLE session_handle)
{
    filter_session_t *session = session_handle;
    if (session->tun_filters[0] == 0)
    {
        return ERROR_SUCCESS;
    }

    DWORD status = FwpmTransactionBegin0(session->engine, 0);
    if (status == ERROR_SUCCESS)
    {
        for (UINT32 i = 0; i < kTunFilterCount && status == ERROR_SUCCESS; ++i)
        {
            status = FwpmFilterDeleteById0(session->engine, session->tun_filters[i]);
            if (status == (DWORD) FWP_E_FILTER_NOT_FOUND)
            {
                status = ERROR_SUCCESS;
            }
        }
        if (status == ERROR_SUCCESS)
        {
            GUID key = filterKey(kTunGrant);
            status   = FwpmProviderContextDeleteByKey0(session->engine, &key);
        }
        status = finishTransaction(session->engine, status);
        if (status == ERROR_SUCCESS)
        {
            memset(session->tun_filters, 0, sizeof(session->tun_filters));
            InterlockedExchange(&filter_inventory_changed, 1);
        }
    }
    return status;
}

DWORD launcherKillSwitchVerifySession(HANDLE session_handle, bool tun_granted)
{
    filter_session_t *session  = session_handle;
    grant_ids_t       expected = {.session = session->session_key};
    if (session->image_filters[0] == 0 || (session->tun_filters[0] != 0) != tun_granted)
        return ERROR_INVALID_DATA;
    memcpy(expected.image, session->image_filters, sizeof(expected.image));
    memcpy(expected.tun, session->tun_filters, sizeof(expected.tun));
    /* BFE change notifications are best effort. Periodically recheck the
     * whole sublayer even when no notification has arrived. */
    bool inventory =
        InterlockedExchange(&filter_inventory_changed, 0) != 0 || GetTickCount64() >= session->next_inventory_check;
    DWORD status = FwpmTransactionBegin0(session->engine, FWPM_TXN_READ_ONLY);
    if (status != ERROR_SUCCESS)
        return status;
    bool present = false;
    bool valid   = false;
    status       = inspectRules(session->engine, &session->dhcp, NULL, &expected, inventory, &present, &valid);
    if (status == ERROR_SUCCESS && (! present || ! valid))
        status = ERROR_INVALID_DATA;
    status = finishTransaction(session->engine, status);
    if (status == ERROR_SUCCESS && inventory)
        session->next_inventory_check = GetTickCount64() + kInventoryIntervalMs;
    return status;
}

void launcherKillSwitchCloseSession(HANDLE session_handle)
{
    filter_session_t *session = session_handle;
    if (session != NULL)
    {
        if (session->engine != NULL)
        {
            if (session->subscription != NULL)
                FwpmFilterUnsubscribeChanges0(session->engine, session->subscription);
            DWORD status = FwpmEngineClose0(session->engine);
            if (status != ERROR_SUCCESS && status != (DWORD) FWP_E_SESSION_ABORTED)
            {
                /* BFE retires dynamic objects on process exit. Keep the
                 * locked image and Job intact until that termination path. */
                TerminateProcess(GetCurrentProcess(), status);
                ExitProcess(status);
            }
        }
        closeDhcpIdentity(&session->dhcp);
        free(session);
    }
}
