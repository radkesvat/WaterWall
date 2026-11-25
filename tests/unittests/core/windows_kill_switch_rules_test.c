/*
 * Covers: Windows kill switch policy construction and verification.
 * Setup: Compile the production backend and capture the filters it would submit.
 * Cases: Physical IPv4 error replies, forwarding, owned TUN exceptions,
 * policy verification, reconciliation and selective removal during unlock.
 * Limits: Does not modify Windows network policy or exercise packet classification.
 * CTest: waterwall.windows_kill_switch_rules_unit
 */
#include "../../../core/launcher/kill_switch_wfp.h"
#include <fwpmu.h>

static FWPM_FILTER0 captured_filter;
static unsigned     filter_additions;
static unsigned     filter_deletions;

static DWORD captureFilter(HANDLE engine, const FWPM_FILTER0 *filter, PSECURITY_DESCRIPTOR security, UINT64 *id)
{
    (void) engine;
    (void) security;
    (void) id;
    ++filter_additions;
    captured_filter                 = *filter;
    captured_filter.effectiveWeight = filter->weight;
    captured_filter.filterId        = 1;
    return ERROR_SUCCESS;
}

static DWORD        lookupUnlockFilter(HANDLE engine, const GUID *key, FWPM_FILTER0 **filter);
static DWORD        removeUnlockFilter(HANDLE engine, const GUID *key);
static DWORD        lookupUnlockSublayer(HANDLE engine, const GUID *key, FWPM_SUBLAYER0 **sublayer);
static DWORD        removeUnlockSublayer(HANDLE engine, const GUID *key);
static DWORD WINAPI readFilterSecurity(HANDLE engine, const GUID *key, SECURITY_INFORMATION info, PSID *owner,
                                       PSID *group, PACL *acl, PACL *sacl, PSECURITY_DESCRIPTOR *descriptor);
static void         releaseLookup(void **result);

#define FwpmFilterAdd0                  captureFilter
#define FwpmFilterGetByKey0             lookupUnlockFilter
#define FwpmFilterGetSecurityInfoByKey0 readFilterSecurity
#define FwpmFilterDeleteByKey0          removeUnlockFilter
#define FwpmSubLayerGetByKey0           lookupUnlockSublayer
#define FwpmSubLayerDeleteByKey0        removeUnlockSublayer
#define FwpmFreeMemory0                 releaseLookup
#include "../../../core/launcher/kill_switch_wfp.c"
#undef FwpmFilterAdd0
#undef FwpmFilterGetByKey0
#undef FwpmFilterGetSecurityInfoByKey0
#undef FwpmFilterDeleteByKey0
#undef FwpmSubLayerGetByKey0
#undef FwpmSubLayerDeleteByKey0
#undef FwpmFreeMemory0

#include "test_assert.h"
#define CHECK(expression)                                                                                              \
    do                                                                                                                 \
    {                                                                                                                  \
        if (! TEST_CHECK(expression, "unexpected WFP policy"))                                                         \
            return 1;                                                                                                  \
    } while (0)

static filter_spec_t *findRule(filter_spec_t *rules, size_t count, UINT32 offset)
{
    for (size_t i = 0; i < count; ++i)
        if (rules[i].key_offset == offset)
            return &rules[i];
    return NULL;
}

static int checkErrorRules(void)
{
    filter_spec_t   baseline[kBaseFilterCount], tun[kTunFilterCount];
    dhcp_identity_t dhcp  = {0};
    UINT64          luid  = 0x123456789ULL;
    NET_IFINDEX     index = 31;
    baseRules(baseline, &dhcp);
    tunRules(tun, &luid, index);

    filter_spec_t *icmp = findRule(baseline, ARRAYSIZE(baseline), kIp4IcmpErrorDeny);
    CHECK(icmp && IsEqualGUID(icmp->layer, &outbound_icmp_error_v4));
    CHECK(icmp->action == FWP_ACTION_BLOCK && icmp->flags == FWPM_FILTER_FLAG_PERSISTENT && icmp->condition_count == 0);
    filter_spec_t *loop = findRule(baseline, ARRAYSIZE(baseline), kIp4IcmpErrorLoopback);
    CHECK(loop && IsEqualGUID(loop->layer, icmp->layer) && loop->flags == FWPM_FILTER_FLAG_PERSISTENT);
    CHECK(loop->action == FWP_ACTION_PERMIT && loop->weight > icmp->weight && loop->condition_count == 1);
    CHECK(IsEqualGUID(&loop->conditions[0].fieldKey, &condition_flags) &&
          loop->conditions[0].matchType == FWP_MATCH_FLAGS_ALL_SET &&
          loop->conditions[0].conditionValue.uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK);

    filter_spec_t *tcp = findRule(baseline, ARRAYSIZE(baseline), kIp4TcpSilentDrop);
    CHECK(tcp && IsEqualGUID(tcp->layer, &inbound_transport_v4_discard) && tcp->flags == FWPM_FILTER_FLAG_PERSISTENT);
    CHECK(tcp->condition_count == 2 && IsEqualGUID(&tcp->conditions[0].fieldKey, &condition_flags) &&
          tcp->conditions[0].matchType == FWP_MATCH_FLAGS_NONE_SET &&
          tcp->conditions[0].conditionValue.uint32 == FWP_CONDITION_FLAG_IS_LOOPBACK);
    CHECK(IsEqualGUID(&tcp->conditions[1].fieldKey, &condition_protocol) &&
          tcp->conditions[1].matchType == FWP_MATCH_EQUAL && tcp->conditions[1].conditionValue.uint8 == IPPROTO_TCP);
    CHECK(addRule(NULL, tcp, NULL, NULL) == ERROR_SUCCESS);
    CHECK(captured_filter.action.type == FWP_ACTION_CALLOUT_TERMINATING &&
          IsEqualGUID(&captured_filter.action.calloutKey, &transport_v4_silent_drop) &&
          matchesRule(&captured_filter, tcp));
    captured_filter.action.calloutKey = condition_protocol;
    CHECK(! matchesRule(&captured_filter, tcp));

    const filter_spec_t *fallback[] = {icmp, tcp};
    for (size_t i = 0; i < ARRAYSIZE(fallback); ++i)
    {
        const filter_spec_t *grant = findRule(tun, ARRAYSIZE(tun), kTunGrant + 8 + (UINT32) i);
        CHECK(grant && IsEqualGUID(grant->layer, fallback[i]->layer) && grant->action == FWP_ACTION_PERMIT);
        CHECK(grant->flags == 0 && grant->weight > fallback[i]->weight && grant->condition_count == 2);
        CHECK(IsEqualGUID(&grant->conditions[0].fieldKey, &condition_local_interface) &&
              grant->conditions[0].matchType == FWP_MATCH_EQUAL && *grant->conditions[0].conditionValue.uint64 == luid);
        CHECK(IsEqualGUID(&grant->conditions[1].fieldKey, &condition_interface_index) &&
              grant->conditions[1].matchType == FWP_MATCH_EQUAL && grant->conditions[1].conditionValue.uint32 == index);
    }
    return 0;
}

static int checkForwardRules(void)
{
    dhcp_identity_t   dhcp = {0};
    filter_spec_t     baseline[kBaseFilterCount], tun[kTunFilterCount];
    UINT64            luid  = 12345;
    const NET_IFINDEX index = 23;
    baseRules(baseline, &dhcp);
    tunRules(tun, &luid, index);

    filter_spec_t *block = findRule(baseline, ARRAYSIZE(baseline), kIp4ForwardDeny);
    filter_spec_t *boot  = findRule(baseline, ARRAYSIZE(baseline), kIp4BootForwardDeny);
    CHECK(block && IsEqualGUID(block->layer, &forward_v4) && block->flags == FWPM_FILTER_FLAG_PERSISTENT);
    CHECK(boot && IsEqualGUID(boot->layer, &forward_v4) && boot->flags == FWPM_FILTER_FLAG_BOOTTIME);
    CHECK(block->action == FWP_ACTION_BLOCK && block->condition_count == 0);
    CHECK(boot->action == FWP_ACTION_BLOCK && boot->condition_count == 0);

    filter_spec_t *grant = findRule(tun, ARRAYSIZE(tun), kTunGrant + 10);
    CHECK(grant && IsEqualGUID(grant->layer, &forward_v4) && grant->action == FWP_ACTION_PERMIT);
    CHECK(grant->flags == 0 && grant->weight > block->weight && grant->condition_count == 2);
    CHECK(IsEqualGUID(&grant->conditions[0].fieldKey, &condition_forward_interface) &&
          grant->conditions[0].matchType == FWP_MATCH_EQUAL && grant->conditions[0].conditionValue.type == FWP_UINT64 &&
          *grant->conditions[0].conditionValue.uint64 == luid);
    CHECK(IsEqualGUID(&grant->conditions[1].fieldKey, &condition_destination_index) &&
          grant->conditions[1].matchType == FWP_MATCH_EQUAL && grant->conditions[1].conditionValue.type == FWP_UINT32 &&
          grant->conditions[1].conditionValue.uint32 == index);
    return 0;
}

/* Model BFE's rule that an occupied sublayer cannot be deleted. */
static FWPM_FILTER0         unlock_filters[4];
static FWPM_SUBLAYER0       unlock_sublayer;
static bool                 unlock_sublayer_present;
static bool                 unsafe_filter_acl;
static PSECURITY_DESCRIPTOR filter_descriptor;

static DWORD lookupUnlockFilter(HANDLE engine, const GUID *key, FWPM_FILTER0 **result)
{
    (void) engine;
    for (size_t i = 0; i < ARRAYSIZE(unlock_filters); ++i)
        if (unlock_filters[i].filterId != 0 && IsEqualGUID(key, &unlock_filters[i].filterKey))
        {
            *result = &unlock_filters[i];
            return ERROR_SUCCESS;
        }
    return (DWORD) FWP_E_FILTER_NOT_FOUND;
}

static void releaseLookup(void **result)
{
    if (*result != NULL && *result == filter_descriptor)
    {
        LocalFree(filter_descriptor);
        filter_descriptor = NULL;
    }
    *result = NULL;
}

static DWORD WINAPI readFilterSecurity(HANDLE engine, const GUID *key, SECURITY_INFORMATION info, PSID *owner,
                                       PSID *group, PACL *acl, PACL *sacl, PSECURITY_DESCRIPTOR *descriptor)
{
    (void) engine;
    (void) key;
    (void) info;
    (void) group;
    (void) sacl;
    DWORD status =
        makeAcl(unsafe_filter_acl ? L"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;AU)" : policy_acl, &filter_descriptor);
    if (status != ERROR_SUCCESS)
        return status;
    *descriptor = filter_descriptor;
    BOOL present, defaulted;
    if (! GetSecurityDescriptorOwner(*descriptor, owner, &defaulted) ||
        ! GetSecurityDescriptorDacl(*descriptor, &present, acl, &defaulted))
        return GetLastError();
    return ERROR_SUCCESS;
}

static DWORD removeUnlockFilter(HANDLE engine, const GUID *key)
{
    FWPM_FILTER0 *filter = NULL;
    DWORD         status = lookupUnlockFilter(engine, key, &filter);
    if (status == ERROR_SUCCESS)
    {
        ++filter_deletions;
        filter->filterId = 0;
    }
    return status;
}

static DWORD lookupUnlockSublayer(HANDLE engine, const GUID *key, FWPM_SUBLAYER0 **result)
{
    (void) engine;
    if (! unlock_sublayer_present || ! IsEqualGUID(key, &waterwall_sublayer))
        return (DWORD) FWP_E_SUBLAYER_NOT_FOUND;
    *result = &unlock_sublayer;
    return ERROR_SUCCESS;
}

static DWORD removeUnlockSublayer(HANDLE engine, const GUID *key)
{
    (void) engine;
    if (! unlock_sublayer_present || ! IsEqualGUID(key, &waterwall_sublayer))
        return (DWORD) FWP_E_SUBLAYER_NOT_FOUND;
    for (size_t i = 0; i < ARRAYSIZE(unlock_filters); ++i)
        if (unlock_filters[i].filterId != 0 && IsEqualGUID(key, &unlock_filters[i].subLayerKey))
            return (DWORD) FWP_E_IN_USE;
    unlock_sublayer_present = false;
    return ERROR_SUCCESS;
}

static int checkIncompleteUnlock(void)
{
    GUID foreign_provider = filterKey(0xdef);
    unlock_filters[0]     = (FWPM_FILTER0) {.filterId         = 1,
                                            .filterKey        = filterKey(kIp4ForwardDeny),
                                            .subLayerKey      = waterwall_sublayer,
                                            .displayData.name = L"WaterWall default block"};
    unlock_filters[1]     = (FWPM_FILTER0) {.filterId = 2, .filterKey = filterKey(kAleDeny), .subLayerKey = empty_key};
    unlock_filters[2] =
        (FWPM_FILTER0) {.filterId = 3, .filterKey = filterKey(0xabc), .subLayerKey = waterwall_sublayer};
    unlock_filters[3]                = (FWPM_FILTER0) {.filterId         = 4,
                                                       .filterKey        = filterKey(kAleLoopback),
                                                       .subLayerKey      = waterwall_sublayer,
                                                       .displayData.name = L"WaterWall permit loopback",
                                                       .providerKey      = &foreign_provider};
    unlock_sublayer_present          = true;
    unlock_sublayer.displayData.name = L"Another provider";
    bool retained                    = false;
    CHECK(unlockRules(NULL, &retained) == ERROR_SUCCESS && retained && unlock_sublayer_present);
    CHECK(unlock_filters[0].filterId == 1);
    unlock_sublayer.displayData.name = sublayer_name;
    retained                         = false;
    CHECK(unlockRules(NULL, &retained) == ERROR_SUCCESS && retained && unlock_sublayer_present);
    CHECK(unlock_filters[0].filterId == 0 && unlock_filters[1].filterId == 2 && unlock_filters[2].filterId == 3 &&
          unlock_filters[3].filterId == 4);

    unlock_filters[2].filterId = 0;
    unlock_filters[3].filterId = 0;
    retained                   = false;
    CHECK(unlockRules(NULL, &retained) == ERROR_SUCCESS && ! retained && ! unlock_sublayer_present);
    CHECK(unlockRules(NULL, &retained) == ERROR_SUCCESS && ! retained);
    CHECK(unlock_filters[1].filterId == 2);
    return 0;
}

static int checkReconciliation(void)
{
    filter_spec_t rule = denyRule(kIp4ForwardDeny, &forward_v4, FWPM_FILTER_FLAG_PERSISTENT);
    CHECK(addRule(NULL, &rule, NULL, NULL) == ERROR_SUCCESS);
    unlock_filters[0] = captured_filter;
    unlock_filters[1] = unlock_filters[2] = unlock_filters[3] = (FWPM_FILTER0) {0};
    filter_additions = filter_deletions = 0;
    PSECURITY_DESCRIPTOR acl            = NULL;
    CHECK(makeAcl(policy_acl, &acl) == ERROR_SUCCESS);

    bool valid = true;
    CHECK(inspectBaseRule(NULL, &rule, acl, true, false, &valid) == ERROR_SUCCESS && valid);
    CHECK(filter_additions == 0 && filter_deletions == 0);

    unlock_filters[0].flags = FWPM_FILTER_FLAG_BOOTTIME;
    CHECK(inspectBaseRule(NULL, &rule, NULL, true, false, &valid) == ERROR_SUCCESS && ! valid);
    CHECK(filter_additions == 0 && filter_deletions == 0);
    CHECK(inspectBaseRule(NULL, &rule, acl, true, false, &valid) == ERROR_SUCCESS && valid);
    CHECK(filter_additions == 1 && filter_deletions == 1 && matchesRule(&captured_filter, &rule));

    CHECK(inspectBaseRule(NULL, &rule, NULL, true, false, &valid) == ERROR_SUCCESS && ! valid);
    CHECK(inspectBaseRule(NULL, &rule, acl, true, false, &valid) == ERROR_SUCCESS && valid);
    CHECK(filter_additions == 2 && filter_deletions == 1);
    unlock_filters[0] = captured_filter;

    unsafe_filter_acl = true;
    CHECK(inspectBaseRule(NULL, &rule, acl, true, false, &valid) == ERROR_SUCCESS && ! valid);
    unsafe_filter_acl                  = false;
    unlock_filters[0].displayData.name = L"A foreign filter";
    CHECK(inspectBaseRule(NULL, &rule, acl, true, false, &valid) == ERROR_SUCCESS && ! valid);
    CHECK(filter_additions == 2 && filter_deletions == 1 && unlock_filters[0].filterId != 0);
    LocalFree(acl);
    return 0;
}

static bool acceptsPolicySecurity(const wchar_t *sddl)
{
    PSECURITY_DESCRIPTOR descriptor = NULL;
    PSID                 owner      = NULL;
    PACL                 acl        = NULL;
    BOOL                 present = FALSE, defaulted = FALSE;
    bool                 valid =
        makeAcl(sddl, &descriptor) == ERROR_SUCCESS && GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) &&
        GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted) && present && safePolicyAcl(owner, acl);
    LocalFree(descriptor);
    return valid;
}

static int checkRetiringGrants(void)
{
    filter_spec_t rules[] = {
        denyRule(kIp4ForwardDeny, &forward_v4, FWPM_FILTER_FLAG_PERSISTENT),
        denyRule(kIp4BootForwardDeny, &forward_v4, FWPM_FILTER_FLAG_BOOTTIME),
    };
    CHECK(addRule(NULL, &rules[0], NULL, NULL) == ERROR_SUCCESS);
    unlock_filters[0]       = captured_filter;
    unlock_filters[0].flags = FWPM_FILTER_FLAG_BOOTTIME;
    filter_additions = filter_deletions = 0;
    PSECURITY_DESCRIPTOR acl            = NULL;
    CHECK(makeAcl(policy_acl, &acl) == ERROR_SUCCESS);

    bool valid = true;
    CHECK(inspectBaseRules(NULL, rules, ARRAYSIZE(rules), acl, true, true, &valid) == ERROR_RETRY && valid);
    CHECK(filter_additions == 0 && filter_deletions == 0 && unlock_filters[0].filterId != 0);

    unlock_filters[0].displayData.name = L"A foreign filter";
    CHECK(inspectBaseRules(NULL, rules, ARRAYSIZE(rules), acl, true, true, &valid) == ERROR_SUCCESS && ! valid);
    CHECK(filter_additions == 0 && filter_deletions == 0 && unlock_filters[0].filterId != 0);
    LocalFree(acl);
    return 0;
}

static int verifyPolicyCases(void)
{
    CHECK(acceptsPolicySecurity(policy_acl));
    CHECK(! acceptsPolicySecurity(L"O:AUD:P(A;;GA;;;SY)(A;;GA;;;BA)"));
    CHECK(! acceptsPolicySecurity(L"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x2;;;AU)"));
    CHECK(! acceptsPolicySecurity(L"O:BAD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;WD;;;AU)"));
    CHECK(! acceptsPolicySecurity(L"O:BAD:P(A;;GA;;;SY)"));

    GUID                   first_run = filterKey(0x123), second_run = filterKey(0x456), session_key = {0};
    UINT64                 issued[] = {37, 38}, decoded[2] = {0};
    FWP_BYTE_BLOB          blob   = {sizeof(issued), (UINT8 *) issued};
    FWPM_PROVIDER_CONTEXT0 record = {0};
    record.type                   = FWPM_GENERAL_CONTEXT;
    record.displayData.name       = grant_record_name;
    record.providerData           = (FWP_BYTE_BLOB) {sizeof(GUID), (UINT8 *) &first_run};
    record.dataBuffer             = &blob;
    CHECK(decodeGrantIds(&record, decoded, ARRAYSIZE(decoded), &session_key));
    CHECK(IsEqualGUID(&session_key, &first_run) && memcmp(issued, decoded, sizeof(issued)) == 0);
    record.displayData.name = L"A foreign grant record";
    CHECK(! decodeGrantIds(&record, decoded, ARRAYSIZE(decoded), &session_key));
    record.displayData.name  = grant_record_name;
    record.providerData.data = (UINT8 *) &second_run;
    CHECK(! decodeGrantIds(&record, decoded, ARRAYSIZE(decoded), &session_key));
    record.providerData.data = (UINT8 *) &first_run;
    issued[0]                = 0;
    CHECK(! decodeGrantIds(&record, decoded, ARRAYSIZE(decoded), &session_key));

    dhcp_identity_t dhcp = {0};
    filter_spec_t   base[kBaseFilterCount];
    baseRules(base, &dhcp);
    grant_ids_t  grants     = {0};
    FWPM_FILTER0 permit     = {0};
    permit.subLayerKey      = waterwall_sublayer;
    permit.filterKey        = filterKey(kTunGrant + kTunFilterCount);
    permit.filterId         = 123;
    permit.action.type      = FWP_ACTION_PERMIT;
    permit.displayData.name = interface_grant_name;
    CHECK(! knownFilter(&permit, base, &grants)); /* Additional same-sublayer permit. */

    permit.filterKey = filterKey(kImageGrant);
    CHECK(! knownFilter(&permit, base, &grants)); /* No run owns this exception. */
    grants.image[0] = permit.filterId;
    CHECK(knownFilter(&permit, base, &grants));
    permit.filterId++;
    CHECK(! knownFilter(&permit, base, &grants)); /* Replacement using the same GUID. */

    permit.filterKey = filterKey(kTunGrant);
    CHECK(! knownFilter(&permit, base, &grants)); /* Image-only phase. */
    grants.tun[0] = permit.filterId;
    CHECK(knownFilter(&permit, base, &grants));
    permit.flags = FWPM_FILTER_FLAG_PERSISTENT;
    CHECK(! knownFilter(&permit, base, &grants));
    permit.subLayerKey = empty_key;
    CHECK(knownFilter(&permit, base, &grants)); /* Another provider's sublayer is out of scope. */
    return 0;
}

int main(void)
{
    return checkErrorRules() != 0 || checkForwardRules() != 0 || verifyPolicyCases() != 0 ||
           checkIncompleteUnlock() != 0 || checkReconciliation() != 0 || checkRetiringGrants() != 0;
}
