#pragma once

/*
 * Node library registry and dynamic loader interfaces.
 */

#include "wlibc.h"

#include "objects/node.h"

/* The historical descriptor symbol name is retained, but the version gates the
 * complete external-node ABI, including buffer and device APIs. */
#define WW_EXTERNAL_NODE_ABI_REVISION 12u
#ifdef OS_WIN
/* The high bits identify the layout of atomics embedded in public structures.
 * Both tagged values must differ from descriptors built before this check. */
#define WW_EXTERNAL_NODE_ABI_FOR_ATOMICS(c11) (WW_EXTERNAL_NODE_ABI_REVISION | ((c11) ? 0x10000u : 0x20000u))
#define WW_EXTERNAL_NODE_ABI_VERSION          WW_EXTERNAL_NODE_ABI_FOR_ATOMICS(WW_HAVE_C11_ATOMICS)
#else
#define WW_EXTERNAL_NODE_ABI_VERSION WW_EXTERNAL_NODE_ABI_REVISION
#endif
#define WW_EXTERNAL_NODE_LIFECYCLE_ABI_VERSION WW_EXTERNAL_NODE_ABI_VERSION
#define WW_EXTERNAL_NODE_LIFECYCLE_ABI_SYMBOL  "waterwallNodeLifecycleAbiVersion"

typedef uint32_t (*node_lifecycle_abi_version_fn)(void);

/**
 * @brief Load a node library entry by node type name.
 *
 * @param name Node type name.
 * @return node_t Loaded node definition, or zeroed node on failure.
 */
node_t nodelibraryLoadByTypeName(const char *name);

/**
 * @brief Load a node library entry by node type hash.
 *
 * @param htype Node type hash.
 * @return node_t Loaded node definition, or zeroed node on failure.
 */
node_t nodelibraryLoadByTypeHash(hash_t htype);

/**
 * @brief Set preferred directory used for dynamic node library lookup.
 *
 * @param path Search path, or NULL to clear.
 */
void nodelibrarySetSearchPath(const char *path);

/**
 * @brief Register a statically provided node library entry.
 *
 * @param lib Node definition to register.
 */
void nodelibraryRegister(node_t lib);

/**
 * @brief Check if a node can act as a chain head.
 *
 * @param node Node definition.
 * @return true Node has chain-head capability.
 * @return false Node cannot be chain head.
 */
bool nodeHasFlagChainHead(node_t *node);

/**
 * @brief Cleanup node library state and unload dynamically loaded libraries.
 */
void nodelibraryCleanup(void);
