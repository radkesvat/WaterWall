#include "net/node_layer_solver.h"

/*
 * Implementation of node layer graph construction, constraint propagation,
 * and topology validation.
 */


#include "net/chain.h"
#include "net/tunnel.h"
#include "objects/node.h"

typedef struct node_layer_edge_s
{
    tunnel_t           *from;
    tunnel_t           *to;
    bool                from_participates;
    bool                to_participates;
    node_layer_domain_t domain;

} node_layer_edge_t;

typedef enum relation_kind_e
{
    kRelationSameAs   = 1,
    kRelationOpposite = 2

} relation_kind_t;

typedef struct node_layer_relation_s
{
    relation_kind_t      kind;
    node_layer_edge_t   *e_left;
    node_layer_edge_t   *e_right;
    const tunnel_t      *tunnel;
    const tunnel_t      *secondary_tunnel;
    tunnel_layer_side_t  left_side;
    tunnel_layer_side_t  right_side;

} node_layer_relation_t;

static bool tunnelIsInChain(const tunnel_chain_t *chain, const tunnel_t *t)
{
    if (t == NULL)
    {
        return false;
    }
    for (uint16_t i = 0; i < chain->tunnels.len; i++)
    {
        if (chain->tunnels.tuns[i] == t)
        {
            return true;
        }
    }
    return false;
}

static node_layer_edge_t *findEdge(node_layer_edge_t *edges, int edge_count, const tunnel_t *from, const tunnel_t *to)
{
    for (int i = 0; i < edge_count; i++)
    {
        if (edges[i].from == from && edges[i].to == to)
        {
            return &edges[i];
        }
    }
    return NULL;
}

static node_layer_edge_t *findOrAddEdge(node_layer_edge_t *edges, int *edge_count, tunnel_t *from, tunnel_t *to)
{
    node_layer_edge_t *existing = findEdge(edges, *edge_count, from, to);
    if (existing != NULL)
    {
        return existing;
    }
    node_layer_edge_t *e = &edges[(*edge_count)++];
    e->from              = from;
    e->to                = to;
    e->from_participates = false;
    e->to_participates   = false;
    e->domain            = kLayerDomainAny;
    return e;
}

static void addRelation(node_layer_relation_t *relations, int *relation_count,
                        relation_kind_t kind, node_layer_edge_t *e_left,
                        node_layer_edge_t *e_right, const tunnel_t *tunnel,
                        const tunnel_t *secondary_tunnel,
                        tunnel_layer_side_t left_side,
                        tunnel_layer_side_t right_side)
{
    for (int i = 0; i < *relation_count; i++)
    {
        if (relations[i].kind == kind)
        {
            if (relations[i].e_left == e_left && relations[i].e_right == e_right)
            {
                return;
            }
            if (relations[i].e_left == e_right && relations[i].e_right == e_left)
            {
                return;
            }
        }
    }
    node_layer_relation_t *r = &relations[(*relation_count)++];
    r->kind                  = kind;
    r->e_left                = e_left;
    r->e_right               = e_right;
    r->tunnel                = tunnel;
    r->secondary_tunnel      = secondary_tunnel;
    r->left_side             = left_side;
    r->right_side            = right_side;
}

bool nodeLayerValidateNodeMetadata(const node_t *node, node_layer_solver_status_t *status)
{
    if (node == NULL)
    {
        if (status != NULL)
        {
            status->code = kNodeLayerSolverErrMetadataShape;
            snprintf(status->message, sizeof(status->message), "node pointer is NULL");
        }
        return false;
    }

    const char *name = node->name != NULL ? node->name : (node->type != NULL ? node->type : "unnamed");

    // 1. Validate layer_group: must be exactly one of None, 3, 4, Anything.
    const enum node_layer_group lg = node->layer_group;
    if (lg != kNodeLayerNone && lg != kNodeLayer3 && lg != kNodeLayer4 && lg != kNodeLayerAnything)
    {
        if (status != NULL)
        {
            status->code           = kNodeLayerSolverErrMetadataShape;
            status->primary_tunnel = node->instance;
            if ((lg & (kNodeLayerSameAsPrev | kNodeLayerSameAsNext | kNodeLayerOppositeNext | kNodeLayerOppositePrev)) != 0)
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies layer_group with forbidden relative layer flags (SameAs/Opposite)",
                         name);
            }
            else
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies invalid layer_group (0x%x)",
                         name, (unsigned int) lg);
            }
        }
        return false;
    }

    // 2. Validate layer_group_next_node:
    // Exact legal forms:
    // - kNodeLayerNone
    // - kNodeLayer3
    // - kNodeLayer4
    // - kNodeLayerAnything
    // - kNodeLayerSameAsPrev
    // - kNodeLayer3 | kNodeLayerOppositePrev
    // - kNodeLayer4 | kNodeLayerOppositePrev
    // - kNodeLayerAnything | kNodeLayerOppositePrev
    const enum node_layer_group req_next = node->layer_group_next_node;
    bool next_legal = (req_next == kNodeLayerNone ||
                       req_next == kNodeLayer3 ||
                       req_next == kNodeLayer4 ||
                       req_next == kNodeLayerAnything ||
                       req_next == kNodeLayerSameAsPrev ||
                       req_next == (kNodeLayer3 | kNodeLayerOppositePrev) ||
                       req_next == (kNodeLayer4 | kNodeLayerOppositePrev) ||
                       req_next == (kNodeLayerAnything | kNodeLayerOppositePrev));

    if (! next_legal)
    {
        if (status != NULL)
        {
            status->code           = kNodeLayerSolverErrMetadataShape;
            status->primary_tunnel = node->instance;
            if ((req_next & (kNodeLayerSameAsNext | kNodeLayerOppositeNext)) != 0)
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies layer_group_next_node with forbidden forward-referencing relative flag",
                         name);
            }
            else if ((req_next & kNodeLayerOppositePrev) != 0 && (req_next & kNodeLayerAnything) == 0)
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies layer_group_next_node with Opposite flag without base layer group",
                         name);
            }
            else
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies invalid layer_group_next_node mask (0x%x)",
                         name, (unsigned int) req_next);
            }
        }
        return false;
    }

    // 3. Validate layer_group_prev_node:
    // Exact legal forms:
    // - kNodeLayerNone
    // - kNodeLayer3
    // - kNodeLayer4
    // - kNodeLayerAnything
    // - kNodeLayerSameAsNext
    // - kNodeLayer3 | kNodeLayerOppositeNext
    // - kNodeLayer4 | kNodeLayerOppositeNext
    // - kNodeLayerAnything | kNodeLayerOppositeNext
    const enum node_layer_group req_prev = node->layer_group_prev_node;
    bool prev_legal = (req_prev == kNodeLayerNone ||
                       req_prev == kNodeLayer3 ||
                       req_prev == kNodeLayer4 ||
                       req_prev == kNodeLayerAnything ||
                       req_prev == kNodeLayerSameAsNext ||
                       req_prev == (kNodeLayer3 | kNodeLayerOppositeNext) ||
                       req_prev == (kNodeLayer4 | kNodeLayerOppositeNext) ||
                       req_prev == (kNodeLayerAnything | kNodeLayerOppositeNext));

    if (! prev_legal)
    {
        if (status != NULL)
        {
            status->code           = kNodeLayerSolverErrMetadataShape;
            status->primary_tunnel = node->instance;
            if ((req_prev & (kNodeLayerSameAsPrev | kNodeLayerOppositePrev)) != 0)
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies layer_group_prev_node with forbidden backward-referencing relative flag",
                         name);
            }
            else if ((req_prev & kNodeLayerOppositeNext) != 0 && (req_prev & kNodeLayerAnything) == 0)
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies layer_group_prev_node with Opposite flag without base layer group",
                         name);
            }
            else
            {
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") specifies invalid layer_group_prev_node mask (0x%x)",
                         name, (unsigned int) req_prev);
            }
        }
        return false;
    }

    // 4. Capability / mask consistency
    if (! node->can_have_next && req_next != kNodeLayerNone)
    {
        if (status != NULL)
        {
            status->code           = kNodeLayerSolverErrMetadataShape;
            status->primary_tunnel = node->instance;
            snprintf(status->message, sizeof(status->message),
                     "node (\"%s\") specifies can_have_next = false but specifies layer_group_next_node != kNodeLayerNone",
                     name);
        }
        return false;
    }

    if (! node->can_have_prev && req_prev != kNodeLayerNone)
    {
        if (status != NULL)
        {
            status->code           = kNodeLayerSolverErrMetadataShape;
            status->primary_tunnel = node->instance;
            snprintf(status->message, sizeof(status->message),
                     "node (\"%s\") specifies can_have_prev = false but specifies layer_group_prev_node != kNodeLayerNone",
                     name);
        }
        return false;
    }

    return true;
}

bool nodeLayerSolveChain(tunnel_chain_t *chain, node_layer_solver_status_t *status)
{
    if (chain == NULL)
    {
        if (status != NULL)
        {
            status->code = kNodeLayerSolverErrStructural;
            snprintf(status->message, sizeof(status->message), "chain pointer is NULL");
        }
        return false;
    }

    chain->layer_solution_ready = false;
    chain->contains_packet_node = false;
    memoryZero(chain->resolved_prev_layer, sizeof(chain->resolved_prev_layer));
    memoryZero(chain->resolved_next_layer, sizeof(chain->resolved_next_layer));

    const uint16_t n = chain->tunnels.len;
    if (n == 0)
    {
        chain->layer_solution_ready = true;
        chain->contains_packet_node = false;
        return true;
    }

    // Step 1: Validate metadata shape and structural consistency of each tunnel
    for (uint16_t i = 0; i < n; i++)
    {
        tunnel_t *t = chain->tunnels.tuns[i];
        if (t == NULL || t->node == NULL)
        {
            if (status != NULL)
            {
                status->code = kNodeLayerSolverErrStructural;
                snprintf(status->message, sizeof(status->message),
                         "chain contains NULL tunnel or node at index %u", (unsigned int) i);
            }
            return false;
        }

        if (! nodeLayerValidateNodeMetadata(t->node, status))
        {
            return false;
        }

        const char *name = t->node->name != NULL ? t->node->name : t->node->type;

        if (t->next == NULL && t->prev == NULL && ! (t->node->flags & kNodeFlagNoChain))
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = t;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") is not chained", name);
            }
            return false;
        }

        if ((t->node->flags & (kNodeFlagChainHead | kNodeFlagChainEnd)) == 0 &&
            (t->node->flags & kNodeFlagNoChain) != 0 && (t->next != NULL || t->prev != NULL))
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = t;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") has flag kNodeFlagNoChain but is chained", name);
            }
            return false;
        }

        if (t->next != NULL && ! t->node->can_have_next)
        {
            if (status != NULL)
            {
                status->code             = kNodeLayerSolverErrStructural;
                status->primary_tunnel   = t;
                status->secondary_tunnel = t->next;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") has next node (\"%s\") but specifies can_have_next = false",
                         name, t->next->node != NULL ? t->next->node->name : "unnamed");
            }
            return false;
        }

        if (t->prev != NULL && ! t->node->can_have_prev)
        {
            if (status != NULL)
            {
                status->code             = kNodeLayerSolverErrStructural;
                status->primary_tunnel   = t;
                status->secondary_tunnel = t->prev;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") has previous node (\"%s\") but specifies can_have_prev = false",
                         name, t->prev->node != NULL ? t->prev->node->name : "unnamed");
            }
            return false;
        }

        if (t->next == NULL && ! (t->node->flags & kNodeFlagChainEnd) && ! (t->node->flags & kNodeFlagNoChain))
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = t;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") at the end of the chain but does not have flag kNodeFlagChainEnd", name);
            }
            return false;
        }

        if (t->prev == NULL && ! (t->node->flags & kNodeFlagChainHead) && ! (t->node->flags & kNodeFlagNoChain))
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = t;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") at the start of the chain but does not have flag kNodeFlagChainHead", name);
            }
            return false;
        }

        // Check next/prev pointers belong to this chain
        if (t->next != NULL && ! tunnelIsInChain(chain, t->next))
        {
            if (status != NULL)
            {
                status->code             = kNodeLayerSolverErrStructural;
                status->primary_tunnel   = t;
                status->secondary_tunnel = t->next;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") next node (\"%s\") is not in the same assembled chain",
                         name, t->next->node != NULL ? t->next->node->name : "unnamed");
            }
            return false;
        }

        if (t->prev != NULL && ! tunnelIsInChain(chain, t->prev))
        {
            if (status != NULL)
            {
                status->code             = kNodeLayerSolverErrStructural;
                status->primary_tunnel   = t;
                status->secondary_tunnel = t->prev;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") previous node (\"%s\") is not in the same assembled chain",
                         name, t->prev->node != NULL ? t->prev->node->name : "unnamed");
            }
            return false;
        }

        // Linked side cannot use kNodeLayerNone
        if (t->next != NULL && t->node->layer_group_next_node == kNodeLayerNone)
        {
            if (status != NULL)
            {
                status->code             = kNodeLayerSolverErrStructural;
                status->primary_tunnel   = t;
                status->secondary_tunnel = t->next;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") is linked to next node (\"%s\") but specifies layer_group_next_node = kNodeLayerNone",
                         name, t->next->node->name);
            }
            return false;
        }

        if (t->prev != NULL && t->node->layer_group_prev_node == kNodeLayerNone)
        {
            if (status != NULL)
            {
                status->code             = kNodeLayerSolverErrStructural;
                status->primary_tunnel   = t;
                status->secondary_tunnel = t->prev;
                snprintf(status->message, sizeof(status->message),
                         "node (\"%s\") is linked to previous node (\"%s\") but specifies layer_group_prev_node = kNodeLayerNone",
                         name, t->prev->node->name);
            }
            return false;
        }

        // Reciprocal capability on mutual edge
        if (t->next != NULL && t->next->prev == t)
        {
            if (! t->next->node->can_have_prev)
            {
                if (status != NULL)
                {
                    status->code             = kNodeLayerSolverErrStructural;
                    status->primary_tunnel   = t;
                    status->secondary_tunnel = t->next;
                    snprintf(status->message, sizeof(status->message),
                             "node (\"%s\") precedes node (\"%s\") but next node specifies can_have_prev = false",
                             name, t->next->node->name);
                }
                return false;
            }
        }

        // Relative constraints:
        // SameAs is conditional: if either side is missing, it adds no constraint;
        // boundary flags determine if the placement is legal.
        // Opposite is strict: requires BOTH sides present.
        if ((t->node->layer_group_next_node & kNodeLayerOppositePrev) != 0)
        {
            if (t->next == NULL)
            {
                if (status != NULL)
                {
                    status->code           = kNodeLayerSolverErrRelativeMissingSide;
                    status->primary_tunnel = t;
                    snprintf(status->message, sizeof(status->message),
                             "node (\"%s\") specifies layer_group_next_node as %s but has no next node",
                             name, nodeLayerGroupToString(t->node->layer_group_next_node));
                }
                return false;
            }
            if (t->prev == NULL)
            {
                if (status != NULL)
                {
                    status->code           = kNodeLayerSolverErrRelativeMissingSide;
                    status->primary_tunnel = t;
                    snprintf(status->message, sizeof(status->message),
                             "node (\"%s\") specifies layer_group_next_node as %s but has no previous node",
                             name, nodeLayerGroupToString(t->node->layer_group_next_node));
                }
                return false;
            }
        }

        if ((t->node->layer_group_prev_node & kNodeLayerOppositeNext) != 0)
        {
            if (t->prev == NULL)
            {
                if (status != NULL)
                {
                    status->code           = kNodeLayerSolverErrRelativeMissingSide;
                    status->primary_tunnel = t;
                    snprintf(status->message, sizeof(status->message),
                             "node (\"%s\") specifies layer_group_prev_node as %s but has no previous node",
                             name, nodeLayerGroupToString(t->node->layer_group_prev_node));
                }
                return false;
            }
            if (t->next == NULL)
            {
                if (status != NULL)
                {
                    status->code           = kNodeLayerSolverErrRelativeMissingSide;
                    status->primary_tunnel = t;
                    snprintf(status->message, sizeof(status->message),
                             "node (\"%s\") specifies layer_group_prev_node as %s but has no next node",
                             name, nodeLayerGroupToString(t->node->layer_group_prev_node));
                }
                return false;
            }
        }
    }

    // Step 2: Build callback edge graph
    node_layer_edge_t edges[kMaxChainLen * 2];
    int               edge_count = 0;

    for (uint16_t i = 0; i < n; i++)
    {
        tunnel_t *t = chain->tunnels.tuns[i];
        if (t->next != NULL)
        {
            node_layer_edge_t *e = findOrAddEdge(edges, &edge_count, t, t->next);
            e->from_participates = true;
        }
        if (t->prev != NULL)
        {
            node_layer_edge_t *e = findOrAddEdge(edges, &edge_count, t->prev, t);
            e->to_participates   = true;
        }
    }

    // Step 3: Seed edge domains
    for (int e = 0; e < edge_count; e++)
    {
        node_layer_edge_t *edge = &edges[e];

        if (edge->from_participates)
        {
            tunnel_t *from = edge->from;
            edge->domain &= nodeLayerGroupToDomain(from->node->layer_group);
            if ((from->node->layer_group_next_node & kNodeLayerAnything) != 0)
            {
                edge->domain &= nodeLayerGroupToDomain(from->node->layer_group_next_node & kNodeLayerAnything);
            }
            if (edge->domain == kLayerDomainEmpty)
            {
                if (status != NULL)
                {
                    status->code             = kNodeLayerSolverErrConflict;
                    status->primary_tunnel   = from;
                    status->secondary_tunnel = edge->to;
                    snprintf(status->message, sizeof(status->message),
                             "node (\"%s\") (layer %s) requires next node layer %s, but edge domain resolved to empty",
                             from->node->name,
                             nodeLayerGroupToString(from->node->layer_group),
                             nodeLayerGroupToString(from->node->layer_group_next_node));
                }
                return false;
            }
        }

        if (edge->to_participates)
        {
            tunnel_t *to = edge->to;
            node_layer_domain_t to_dom = nodeLayerGroupToDomain(to->node->layer_group);
            if ((edge->domain & to_dom) == kLayerDomainEmpty)
            {
                if (status != NULL)
                {
                    status->code             = kNodeLayerSolverErrConflict;
                    status->primary_tunnel   = edge->from;
                    status->secondary_tunnel = to;
                    if (edge->from_participates)
                    {
                        snprintf(status->message, sizeof(status->message),
                                 "node (\"%s\") (layer %s) is adjacent to next node (\"%s\") with incompatible layer %s",
                                 edge->from->node->name,
                                 nodeLayerGroupToString(edge->from->node->layer_group),
                                 to->node->name,
                                 nodeLayerGroupToString(to->node->layer_group));
                    }
                    else
                    {
                        snprintf(status->message, sizeof(status->message),
                                 "node (\"%s\") (layer %s) requires previous node layer %s, but previous node (\"%s\") has incompatible layer %s",
                                 to->node->name,
                                 nodeLayerGroupToString(to->node->layer_group),
                                 nodeLayerGroupToString(to->node->layer_group_prev_node),
                                 edge->from->node->name,
                                 nodeLayerGroupToString(edge->from->node->layer_group));
                    }
                }
                return false;
            }
            edge->domain &= to_dom;

            if ((to->node->layer_group_prev_node & kNodeLayerAnything) != 0)
            {
                node_layer_domain_t prev_req_dom = nodeLayerGroupToDomain(to->node->layer_group_prev_node & kNodeLayerAnything);
                if ((edge->domain & prev_req_dom) == kLayerDomainEmpty)
                {
                    if (status != NULL)
                    {
                        status->code             = kNodeLayerSolverErrConflict;
                        status->primary_tunnel   = to;
                        status->secondary_tunnel = edge->from;
                        snprintf(status->message, sizeof(status->message),
                                 "node (\"%s\") (layer %s) requires previous node layer %s, but previous node (\"%s\") has incompatible layer %s",
                                 to->node->name,
                                 nodeLayerGroupToString(to->node->layer_group),
                                 nodeLayerGroupToString(to->node->layer_group_prev_node),
                                 edge->from->node->name,
                                 nodeLayerGroupToString(edge->from->node->layer_group));
                    }
                    return false;
                }
                edge->domain &= prev_req_dom;
            }
        }
    }

    // Step 4: Add relations
    node_layer_relation_t relations[kMaxChainLen * 4];
    int                   relation_count = 0;

    for (uint16_t i = 0; i < n; i++)
    {
        tunnel_t *t = chain->tunnels.tuns[i];
        if (t->prev != NULL && t->next != NULL)
        {
            node_layer_edge_t *e_prev = findEdge(edges, edge_count, t->prev, t);
            node_layer_edge_t *e_next = findEdge(edges, edge_count, t, t->next);

            if (e_prev != NULL && e_prev->to_participates && e_next != NULL && e_next->from_participates)
            {
                if (t->node->layer_group_next_node == kNodeLayerSameAsPrev)
                {
                    addRelation(relations, &relation_count, kRelationSameAs, e_prev, e_next, t, NULL, kTunnelLayerSidePrev, kTunnelLayerSideNext);
                }
                if ((t->node->layer_group_next_node & kNodeLayerOppositePrev) != 0)
                {
                    addRelation(relations, &relation_count, kRelationOpposite, e_prev, e_next, t, NULL, kTunnelLayerSidePrev, kTunnelLayerSideNext);
                }
                if (t->node->layer_group_prev_node == kNodeLayerSameAsNext)
                {
                    addRelation(relations, &relation_count, kRelationSameAs, e_prev, e_next, t, NULL, kTunnelLayerSidePrev, kTunnelLayerSideNext);
                }
                if ((t->node->layer_group_prev_node & kNodeLayerOppositeNext) != 0)
                {
                    addRelation(relations, &relation_count, kRelationOpposite, e_prev, e_next, t, NULL, kTunnelLayerSidePrev, kTunnelLayerSideNext);
                }
            }
        }
    }

    // Step 4b: Add registered layer relations
    for (uint16_t k = 0; k < chain->layer_relations_count; k++)
    {
        const tunnel_layer_relation_registration_t *reg = &chain->layer_relations[k];

        if (! tunnelIsInChain(chain, reg->left_tunnel))
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = reg->left_tunnel;
                snprintf(status->message, sizeof(status->message),
                         "registered layer relation references tunnel (\"%s\") which is not in chain",
                         reg->left_tunnel->node != NULL ? reg->left_tunnel->node->name : "unnamed");
            }
            return false;
        }

        if (! tunnelIsInChain(chain, reg->right_tunnel))
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = reg->right_tunnel;
                snprintf(status->message, sizeof(status->message),
                         "registered layer relation references tunnel (\"%s\") which is not in chain",
                         reg->right_tunnel->node != NULL ? reg->right_tunnel->node->name : "unnamed");
            }
            return false;
        }

        node_layer_edge_t *e_left = NULL;
        if (reg->left_side == kTunnelLayerSidePrev)
        {
            if (reg->left_tunnel->prev != NULL)
            {
                e_left = findEdge(edges, edge_count, reg->left_tunnel->prev, reg->left_tunnel);
                if (e_left != NULL && ! e_left->to_participates)
                {
                    e_left = NULL;
                }
            }
        }
        else
        {
            if (reg->left_tunnel->next != NULL)
            {
                e_left = findEdge(edges, edge_count, reg->left_tunnel, reg->left_tunnel->next);
                if (e_left != NULL && ! e_left->from_participates)
                {
                    e_left = NULL;
                }
            }
        }

        node_layer_edge_t *e_right = NULL;
        if (reg->right_side == kTunnelLayerSidePrev)
        {
            if (reg->right_tunnel->prev != NULL)
            {
                e_right = findEdge(edges, edge_count, reg->right_tunnel->prev, reg->right_tunnel);
                if (e_right != NULL && ! e_right->to_participates)
                {
                    e_right = NULL;
                }
            }
        }
        else
        {
            if (reg->right_tunnel->next != NULL)
            {
                e_right = findEdge(edges, edge_count, reg->right_tunnel, reg->right_tunnel->next);
                if (e_right != NULL && ! e_right->from_participates)
                {
                    e_right = NULL;
                }
            }
        }

        if (e_left == NULL && e_right == NULL)
        {
            continue;
        }

        if (e_left == NULL)
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = reg->left_tunnel;
                snprintf(status->message, sizeof(status->message),
                         "registered layer relation for tunnel (\"%s\") %s side has no participating edge",
                         reg->left_tunnel->node != NULL ? reg->left_tunnel->node->name : "unnamed",
                         reg->left_side == kTunnelLayerSidePrev ? "previous" : "next");
            }
            return false;
        }

        if (e_right == NULL)
        {
            if (status != NULL)
            {
                status->code           = kNodeLayerSolverErrStructural;
                status->primary_tunnel = reg->right_tunnel;
                snprintf(status->message, sizeof(status->message),
                         "registered layer relation for tunnel (\"%s\") %s side has no participating edge",
                         reg->right_tunnel->node != NULL ? reg->right_tunnel->node->name : "unnamed",
                         reg->right_side == kTunnelLayerSidePrev ? "previous" : "next");
            }
            return false;
        }

        relation_kind_t rkind = (reg->kind == kTunnelLayerRelationSame) ? kRelationSameAs : kRelationOpposite;
        addRelation(relations, &relation_count, rkind, e_left, e_right, reg->left_tunnel, reg->right_tunnel, reg->left_side, reg->right_side);
    }

    // Step 5: Propagate relations monotonically to fixed point
    bool changed        = true;
    int  iterations     = 0;
    int  max_iterations = 2 * edge_count + 2;

    while (changed)
    {
        changed = false;
        iterations++;
        if (iterations > max_iterations)
        {
            if (status != NULL)
            {
                status->code = kNodeLayerSolverErrConvergence;
                snprintf(status->message, sizeof(status->message),
                         "layer solver did not converge within %d iterations", max_iterations);
            }
            return false;
        }

        for (int r = 0; r < relation_count; r++)
        {
            node_layer_relation_t *rel     = &relations[r];
            node_layer_edge_t     *e_left  = rel->e_left;
            node_layer_edge_t     *e_right = rel->e_right;

            if (rel->kind == kRelationSameAs)
            {
                node_layer_domain_t inter = e_left->domain & e_right->domain;
                if (inter == kLayerDomainEmpty)
                {
                    if (status != NULL)
                    {
                        status->code             = kNodeLayerSolverErrConflict;
                        status->primary_tunnel   = rel->tunnel;
                        status->secondary_tunnel = rel->secondary_tunnel;
                        if (rel->secondary_tunnel != NULL)
                        {
                            snprintf(status->message, sizeof(status->message),
                                     "registered layer relation between node (\"%s\") %s side and node (\"%s\") %s side requires same layer, but resolved to incompatible domains (%s and %s)",
                                     rel->tunnel->node != NULL ? rel->tunnel->node->name : "unnamed",
                                     rel->left_side == kTunnelLayerSidePrev ? "previous" : "next",
                                     rel->secondary_tunnel->node != NULL ? rel->secondary_tunnel->node->name : "unnamed",
                                     rel->right_side == kTunnelLayerSidePrev ? "previous" : "next",
                                     nodeLayerDomainToString(e_left->domain),
                                     nodeLayerDomainToString(e_right->domain));
                        }
                        else
                        {
                            snprintf(status->message, sizeof(status->message),
                                     "node (\"%s\") (layer %s) requires same layer on both sides, but sides resolved to incompatible domains (%s and %s)",
                                     rel->tunnel->node->name,
                                     nodeLayerGroupToString(rel->tunnel->node->layer_group),
                                     nodeLayerDomainToString(e_left->domain),
                                     nodeLayerDomainToString(e_right->domain));
                        }
                    }
                    return false;
                }
                if (e_left->domain != inter)
                {
                    e_left->domain = inter;
                    changed        = true;
                }
                if (e_right->domain != inter)
                {
                    e_right->domain = inter;
                    changed         = true;
                }
            }
            else if (rel->kind == kRelationOpposite)
            {
                node_layer_domain_t new_left  = e_left->domain & nodeLayerDomainFlip(e_right->domain);
                node_layer_domain_t new_right = e_right->domain & nodeLayerDomainFlip(e_left->domain);

                if (new_left == kLayerDomainEmpty || new_right == kLayerDomainEmpty)
                {
                    if (status != NULL)
                    {
                        status->code             = kNodeLayerSolverErrConflict;
                        status->primary_tunnel   = rel->tunnel;
                        status->secondary_tunnel = rel->secondary_tunnel;
                        if (rel->secondary_tunnel != NULL)
                        {
                            snprintf(status->message, sizeof(status->message),
                                     "registered layer relation between node (\"%s\") %s side and node (\"%s\") %s side requires opposite layers, but resolved to incompatible domains (%s and %s)",
                                     rel->tunnel->node != NULL ? rel->tunnel->node->name : "unnamed",
                                     rel->left_side == kTunnelLayerSidePrev ? "previous" : "next",
                                     rel->secondary_tunnel->node != NULL ? rel->secondary_tunnel->node->name : "unnamed",
                                     rel->right_side == kTunnelLayerSidePrev ? "previous" : "next",
                                     nodeLayerDomainToString(e_left->domain),
                                     nodeLayerDomainToString(e_right->domain));
                        }
                        else
                        {
                            snprintf(status->message, sizeof(status->message),
                                     "node (\"%s\") (layer %s) requires opposite layers on both sides, but sides resolved to incompatible domains (%s and %s)",
                                     rel->tunnel->node->name,
                                     nodeLayerGroupToString(rel->tunnel->node->layer_group),
                                     nodeLayerDomainToString(e_left->domain),
                                     nodeLayerDomainToString(e_right->domain));
                        }
                    }
                    return false;
                }
                if (e_left->domain != new_left)
                {
                    e_left->domain = new_left;
                    changed        = true;
                }
                if (e_right->domain != new_right)
                {
                    e_right->domain = new_right;
                    changed         = true;
                }
            }
        }
    }

    // Step 6: Cache resolved layers and classification into chain
    for (uint16_t i = 0; i < n; i++)
    {
        tunnel_t *t = chain->tunnels.tuns[i];
        if (t->prev != NULL)
        {
            node_layer_edge_t *e = findEdge(edges, edge_count, t->prev, t);
            chain->resolved_prev_layer[i] = (e != NULL && e->to_participates) ? (uint8_t) e->domain : (uint8_t) kLayerDomainEmpty;
        }
        else
        {
            chain->resolved_prev_layer[i] = (uint8_t) kLayerDomainEmpty;
        }

        if (t->next != NULL)
        {
            node_layer_edge_t *e = findEdge(edges, edge_count, t, t->next);
            chain->resolved_next_layer[i] = (e != NULL && e->from_participates) ? (uint8_t) e->domain : (uint8_t) kLayerDomainEmpty;
        }
        else
        {
            chain->resolved_next_layer[i] = (uint8_t) kLayerDomainEmpty;
        }
    }

    // Determine contains_packet_node based on the 3 conditions:
    bool is_packet_chain = false;

    // 1. At least one participating edge is forced to {L3}
    for (int e = 0; e < edge_count; e++)
    {
        if (edges[e].domain == kLayerDomainL3)
        {
            is_packet_chain = true;
            break;
        }
    }

    // 2. A node/side is fixed to L3
    if (! is_packet_chain)
    {
        for (uint16_t i = 0; i < n; i++)
        {
            tunnel_t *t = chain->tunnels.tuns[i];
            if (t->node->layer_group == kNodeLayer3 ||
                (t->next != NULL && (t->node->layer_group_next_node & kNodeLayer3) == kNodeLayer3 && (t->node->layer_group_next_node & kNodeLayer4) == 0) ||
                (t->prev != NULL && (t->node->layer_group_prev_node & kNodeLayer3) == kNodeLayer3 && (t->node->layer_group_prev_node & kNodeLayer4) == 0))
            {
                is_packet_chain = true;
                break;
            }
        }
    }

    // 3. An Opposite relation guarantees that one of its two sides is L3 even if its orientation remains unresolved
    if (! is_packet_chain)
    {
        for (int r = 0; r < relation_count; r++)
        {
            if (relations[r].kind == kRelationOpposite)
            {
                is_packet_chain = true;
                break;
            }
        }
    }

    chain->contains_packet_node = is_packet_chain;
    chain->layer_solution_ready = true;

    return true;
}
