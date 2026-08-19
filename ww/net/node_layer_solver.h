#pragma once

/*
 * Solver and constraint validator for node layer groups and callback edges.
 */

#include "wlibc.h"
#include "objects/node.h"
#include "net/chain.h"
#include "net/tunnel.h"

typedef enum node_layer_domain_e
{
    kLayerDomainEmpty = 0,
    kLayerDomainL3    = 1 << 0,
    kLayerDomainL4    = 1 << 1,
    kLayerDomainAny   = kLayerDomainL3 | kLayerDomainL4

} node_layer_domain_t;

/**
 * @brief Returns the complement of a layer domain ({L3} <-> {L4}, {L3, L4} -> {L3, L4}, {} -> {}).
 */
static inline node_layer_domain_t nodeLayerDomainFlip(node_layer_domain_t domain)
{
    switch (domain)
    {
    case kLayerDomainL3:
        return kLayerDomainL4;
    case kLayerDomainL4:
        return kLayerDomainL3;
    case kLayerDomainAny:
        return kLayerDomainAny;
    case kLayerDomainEmpty:
    default:
        return kLayerDomainEmpty;
    }
}

/**
 * @brief Converts enum node_layer_group base bits to internal two-bit domain.
 */
static inline node_layer_domain_t nodeLayerGroupToDomain(enum node_layer_group group)
{
    node_layer_domain_t d = kLayerDomainEmpty;
    if ((group & kNodeLayer3) != 0)
    {
        d |= kLayerDomainL3;
    }
    if ((group & kNodeLayer4) != 0)
    {
        d |= kLayerDomainL4;
    }
    return d;
}

/**
 * @brief Formats an internal two-bit domain as a human-readable string.
 */
static inline const char *nodeLayerDomainToString(node_layer_domain_t domain)
{
    switch (domain)
    {
    case kLayerDomainEmpty:
        return "{}";
    case kLayerDomainL3:
        return "L3";
    case kLayerDomainL4:
        return "L4";
    case kLayerDomainAny:
        return "{L3, L4}";
    default:
        return "unknown";
    }
}

typedef enum node_layer_solver_code_e
{
    kNodeLayerSolverOk = 0,
    kNodeLayerSolverErrMetadataShape,
    kNodeLayerSolverErrStructural,
    kNodeLayerSolverErrRelativeMissingSide,
    kNodeLayerSolverErrConflict,
    kNodeLayerSolverErrConvergence

} node_layer_solver_code_t;

typedef struct node_layer_solver_status_s
{
    node_layer_solver_code_t code;
    const tunnel_t          *primary_tunnel;
    const tunnel_t          *secondary_tunnel;
    char                     message[512];

} node_layer_solver_status_t;

/**
 * @brief Validates metadata shape and capabilities of a single node.
 *
 * @param node Node descriptor to validate.
 * @param status Out parameter for detailed status / error info.
 * @return true if valid, false otherwise.
 */
bool nodeLayerValidateNodeMetadata(const node_t *node, node_layer_solver_status_t *status);

/**
 * @brief Solves the edge layer domains for an assembled tunnel chain.
 *
 * Inspects all internal tunnels in the chain for metadata shape and structural consistency,
 * constructs the callback edge graph, seeds edge domains, propagates relations to a fixed point,
 * caches the solved edge domains in chain->resolved_{prev,next}_layer, and determines
 * chain->contains_packet_node. The cache remains valid only while chain topology is unchanged;
 * layer-dependent topology expansion must be followed by another solve before indexing.
 *
 * Does NOT call startupFailureRecord().
 *
 * @param chain Assembled tunnel chain.
 * @param status Out parameter for detailed status / error info.
 * @return true if solved successfully, false if validation or solving failed.
 */
bool nodeLayerSolveChain(tunnel_chain_t *chain, node_layer_solver_status_t *status);
