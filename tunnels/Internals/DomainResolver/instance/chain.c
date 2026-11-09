#include "structure.h"

#include "loggers/network_logger.h"

typedef struct domainresolver_dns_head_s
{
    tunnel_t *owner;
} domainresolver_dns_head_t;

static tunnel_t *domainresolverDnsHeadOwner(tunnel_t *head)
{
    return ((domainresolver_dns_head_t *) tunnelGetState(head))->owner;
}

static void domainresolverDnsHeadEst(tunnel_t *head, line_t *line)
{
    tunnelDownStreamEst(domainresolverDnsHeadOwner(head), line);
}

static void domainresolverDnsHeadFinish(tunnel_t *head, line_t *line)
{
    tunnelDownStreamFin(domainresolverDnsHeadOwner(head), line);
}

static void domainresolverDnsHeadPayload(tunnel_t *head, line_t *line, sbuf_t *buffer)
{
    tunnelDownStreamPayload(domainresolverDnsHeadOwner(head), line, buffer);
}

static void domainresolverDnsHeadPause(tunnel_t *head, line_t *line)
{
    tunnelDownStreamPause(domainresolverDnsHeadOwner(head), line);
}

static void domainresolverDnsHeadResume(tunnel_t *head, line_t *line)
{
    tunnelDownStreamResume(domainresolverDnsHeadOwner(head), line);
}

static bool domainresolverDnsPathReturnsToOwner(tunnel_t *t, node_t *target)
{
    // Detect configured structural next cycles before invoking nested onChain.
    for (unsigned depth = 0; target != NULL && depth <= kMaxChainLen; ++depth)
    {
        if (target == t->node || target->instance == t)
            return true;
        if (target->hash_next == 0)
            return false;
        target = nodemanagerGetConfigNodeByHash(t->node->node_manager_config, target->hash_next);
    }
    return true;
}

static tunnel_t *domainresolverCreateDnsHead(tunnel_t *owner)
{
    domainresolver_tstate_t *ts = tunnelGetState(owner);
    ts->dns_head_node           = (node_t) {
                  .name                  = nodeMakeChildName(owner->node, ".dns-head"),
                  .type                  = stringDuplicate("DomainResolverDnsHead"),
                  .flags                 = kNodeFlagChainHead | kNodeFlagSupportsSplice,
                  .layer_group           = kNodeLayer4,
                  .layer_group_next_node = kNodeLayer4,
                  .layer_group_prev_node = kNodeLayerNone,
                  .can_have_next         = true,
    };
    tunnel_t *head = tunnelCreate(&ts->dns_head_node, sizeof(domainresolver_dns_head_t), 0);
    if (head == NULL)
        return NULL;
    ((domainresolver_dns_head_t *) tunnelGetState(head))->owner = owner;
    head->fnEstD                                                = domainresolverDnsHeadEst;
    head->fnFinD                                                = domainresolverDnsHeadFinish;
    head->fnPayloadD                                            = domainresolverDnsHeadPayload;
    head->fnPauseD                                              = domainresolverDnsHeadPause;
    head->fnResumeD                                             = domainresolverDnsHeadResume;
    ts->dns_head_node.instance                                  = head;
    return head;
}

void domainresolverTunnelOnChain(tunnel_t *t, tunnel_chain_t *chain)
{
    domainresolver_tstate_t *ts = tunnelGetState(t);
    tunnelDefaultOnChain(t, chain);
    if (startupFailurePending() || ts->mode == kDomainResolverModeNative)
        return;
    chain = tunnelGetChain(t);

    node_t *target;
    if (ts->mode == kDomainResolverModeDirect)
        target = &ts->dns_connector_node;
    else if (ts->dns_next != NULL)
        target = nodemanagerGetConfigNodeByName(t->node->node_manager_config, ts->dns_next);
    else
    {
        if (t->node->hash_next == 0)
        {
            LOGF("DomainResolver: chain mode requires next when dns-next is omitted");
            startupFailureRecord(1);
            return;
        }
        target = nodemanagerGetConfigNodeByHash(t->node->node_manager_config, t->node->hash_next);
    }
    if (target == NULL || target->instance == NULL)
    {
        LOGF("DomainResolver: DNS egress node is unavailable");
        startupFailureRecord(1);
        return;
    }
    if (domainresolverDnsPathReturnsToOwner(t, target))
    {
        LOGF("DomainResolver: DNS egress contains a structural cycle through its resolver");
        startupFailureRecord(1);
        return;
    }
    if (ts->mode == kDomainResolverModeChain && t->node->hash_next == target->hash_name)
    {
        ts->dns_egress = tunnelGetBranchEntry(t, target->instance);
        if (ts->dns_egress == NULL)
        {
            LOGF("DomainResolver: ordinary next node has no callable DNS branch entry");
            startupFailureRecord(1);
        }
        return;
    }
    if (target->instance->prev != NULL || target->instance->chain == chain)
    {
        LOGF("DomainResolver: DNS egress already belongs to another predecessor or branch");
        startupFailureRecord(1);
        return;
    }

    ts->dns_head = domainresolverCreateDnsHead(t);
    if (ts->dns_head == NULL)
    {
        startupFailureRecord(1);
        return;
    }
    /* A dedicated L4 root keeps the DNS edge separate from the resolver's
     * application-side SameAs layer constraints. It shares indexing and pools. */
    tunnelBind(ts->dns_head, target->instance);
    tunnelchainInsert(chain, ts->dns_head);
    if (startupFailurePending())
        return;
    if (target->instance->chain != NULL)
        tunnelchainCombine(chain, target->instance->chain);
    else
        target->instance->onChain(target->instance, chain);
    if (startupFailurePending())
        return;
    ts->dns_egress = tunnelGetBranchEntry(ts->dns_head, target->instance);
    if (ts->dns_egress == NULL)
    {
        LOGF("DomainResolver: DNS egress has no callable branch entry");
        startupFailureRecord(1);
    }
}

void domainresolverTunnelOnIndex(tunnel_t *t, uint16_t index, uint32_t *mem_offset)
{
    tunnelDefaultOnIndex(t, index, mem_offset);
    domainresolver_tstate_t *ts = tunnelGetState(t);
    if (ts->mode == kDomainResolverModeNative)
        return;
    tunnel_chain_t *chain = tunnelGetChain(t);
    assert(chain->layer_solution_ready);
    for (uint16_t i = 0; i < chain->tunnels.len; ++i)
    {
        if (chain->tunnels.tuns[i] != ts->dns_egress)
            continue;
        if (tunnelchainGetResolvedPrevLayer(chain, i) != kLayerDomainL4)
        {
            LOGF("DomainResolver: DNS egress must provide a layer-4 transport edge");
            startupFailureRecord(1);
        }
        return;
    }
    LOGF("DomainResolver: DNS egress is missing from its assembled chain");
    startupFailureRecord(1);
}
