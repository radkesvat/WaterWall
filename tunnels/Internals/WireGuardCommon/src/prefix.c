#include "WireGuardCommon/prefix.h"

typedef struct route_s
{
    struct route_s *next;
    size_t          id;
    void           *value;
} route_t;

/* A compressed binary trie. Only an installed prefix or a branch has a node.
 * Paths are at most 32 or 128 bits deep, including during overlap checks. */
struct wireguard_prefix_node_s
{
    wireguard_prefix_node_t *child[2];
    route_t                 *routes;
    uint8_t                  address[16];
    unsigned                 bits;
};

static const uint8_t *addressBytes(const ip_addr_t *ip)
{
    return IP_IS_V4(ip) ? (const uint8_t *) &ip_2_ip4(ip)->addr : (const uint8_t *) ip_2_ip6(ip)->addr;
}

static unsigned addressBit(const uint8_t *address, unsigned bit)
{
    return (address[bit / 8] >> (7U - bit % 8)) & 1U;
}

static unsigned commonBits(const uint8_t *a, const uint8_t *b, unsigned start, unsigned limit)
{
    while (start < limit && addressBit(a, start) == addressBit(b, start))
        ++start;
    return start;
}

int wireguardPrefixLength(const ip_addr_t *ip, const ip_addr_t *mask)
{
    if (ip->type != mask->type || (! IP_IS_V4(ip) && ! IP_IS_V6(ip)))
        return -1;
    const unsigned width = IP_IS_V4(ip) ? 32 : 128;
    const uint8_t *bytes = addressBytes(mask);
    unsigned       bit   = 0;
    while (bit < width && addressBit(bytes, bit) != 0)
        ++bit;
    const int length = (int) bit;
    while (bit < width && addressBit(bytes, bit) == 0)
        ++bit;
    return bit == width ? length : -1;
}

static wireguard_prefix_node_t *newNode(const uint8_t *address, unsigned bits)
{
    wireguard_prefix_node_t *node = memoryAllocateZero(sizeof(*node));
    node->bits                    = bits;
    memoryCopy(node->address, address, (bits + 7U) / 8U);
    return node;
}

static bool hasOtherOwner(const route_t *route, size_t id)
{
    /* Entries are unique by ID. */
    return route != NULL && (route->id != id || route->next != NULL);
}

static bool subtreeHasOtherOwner(const wireguard_prefix_node_t *node, size_t id)
{
    return node != NULL && (hasOtherOwner(node->routes, id) || subtreeHasOtherOwner(node->child[0], id) ||
                            subtreeHasOtherOwner(node->child[1], id));
}

bool wireguardPrefixInsert(wireguard_prefix_table_t *table, const ip_addr_t *ip, const ip_addr_t *mask, size_t id,
                           void *value, bool exclusive)
{
    assert(value != NULL);
    const int length = wireguardPrefixLength(ip, mask);
    if (length < 0)
        return false;
    const unsigned            bits    = (unsigned) length;
    const uint8_t            *address = addressBytes(ip);
    wireguard_prefix_node_t **link    = &table->roots[IP_IS_V4(ip) ? 0 : 1];
    unsigned                  known   = 0;
    while (*link != NULL)
    {
        wireguard_prefix_node_t *node    = *link;
        const unsigned           matched = commonBits(node->address, address, known, min(node->bits, bits));
        if (matched < node->bits)
        {
            if (matched == bits && exclusive && subtreeHasOtherOwner(node, id))
                return false;
            wireguard_prefix_node_t *branch                   = newNode(address, matched);
            branch->child[addressBit(node->address, matched)] = node;
            *link                                             = branch;
            if (matched < bits)
                link = &branch->child[addressBit(address, matched)];
            break;
        }
        if (exclusive && hasOtherOwner(node->routes, id))
            return false;
        if (bits == node->bits)
        {
            if (exclusive && (subtreeHasOtherOwner(node->child[0], id) || subtreeHasOtherOwner(node->child[1], id)))
                return false;
            break;
        }
        known = node->bits + 1;
        link  = &node->child[addressBit(address, node->bits)];
    }
    if (*link == NULL)
        *link = newNode(address, bits);
    route_t **entry = &(*link)->routes;
    while (*entry != NULL && (*entry)->id < id)
        entry = &(*entry)->next;
    if (*entry == NULL || (*entry)->id != id)
    {
        route_t *route = memoryAllocate(sizeof(*route));
        *route         = (route_t) {.next = *entry, .id = id, .value = value};
        *entry         = route;
    }
    return true;
}

void *wireguardPrefixLookup(const wireguard_prefix_table_t *table, const ip_addr_t *ip)
{
    if (! IP_IS_V4(ip) && ! IP_IS_V6(ip))
        return NULL;
    const wireguard_prefix_node_t *node    = table->roots[IP_IS_V4(ip) ? 0 : 1];
    const uint8_t                 *address = addressBytes(ip);
    const unsigned                 width   = IP_IS_V4(ip) ? 32 : 128;
    unsigned                       known   = 0;
    void                          *best    = NULL;
    while (node != NULL && commonBits(node->address, address, known, node->bits) == node->bits)
    {
        if (node->routes != NULL)
            best = node->routes->value;
        if (node->bits == width)
            break;
        known = node->bits + 1;
        node  = node->child[addressBit(address, node->bits)];
    }
    return best;
}

static void removeRoute(wireguard_prefix_node_t **link, const uint8_t *address, unsigned known, unsigned bits,
                        size_t id)
{
    wireguard_prefix_node_t *node = *link;
    if (node == NULL || node->bits > bits || commonBits(node->address, address, known, node->bits) != node->bits)
        return;
    if (node->bits < bits)
        removeRoute(&node->child[addressBit(address, node->bits)], address, node->bits + 1, bits, id);
    else
    {
        route_t **entry = &node->routes;
        while (*entry != NULL && (*entry)->id != id)
            entry = &(*entry)->next;
        if (*entry == NULL)
            return;
        route_t *old = *entry;
        *entry       = old->next;
        memoryFree(old);
    }
    if (node->routes == NULL && (node->child[0] == NULL || node->child[1] == NULL))
    {
        *link = node->child[0] != NULL ? node->child[0] : node->child[1];
        memoryFree(node);
    }
}

void wireguardPrefixRemove(wireguard_prefix_table_t *table, const ip_addr_t *ip, const ip_addr_t *mask, size_t id)
{
    const int length = wireguardPrefixLength(ip, mask);
    if (length >= 0)
        removeRoute(&table->roots[IP_IS_V4(ip) ? 0 : 1], addressBytes(ip), 0, (unsigned) length, id);
}

static void freeTree(wireguard_prefix_node_t *node)
{
    if (node == NULL)
        return;
    freeTree(node->child[0]);
    freeTree(node->child[1]);
    while (node->routes != NULL)
    {
        route_t *route = node->routes;
        node->routes   = route->next;
        memoryFree(route);
    }
    memoryFree(node);
}

void wireguardPrefixDestroy(wireguard_prefix_table_t *table)
{
    freeTree(table->roots[0]);
    freeTree(table->roots[1]);
    *table = (wireguard_prefix_table_t) {0};
}
