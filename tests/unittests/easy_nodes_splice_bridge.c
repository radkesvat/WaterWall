#include "BlackHole/interface.h"
#include "Bridge/structure.h"
#include "easy_nodes_splice_fixture.h"

void testBridgeAndBlackHoleSplice(bool splice)
{
    easy_fixture_t f;
    easySetup(&f, tunnelCreate(NULL, sizeof(bridge_tstate_t), sizeof(bridge_lstate_t)));
    tunnel_t *pair = tunnelCreate(NULL, sizeof(bridge_tstate_t), 0);
    easyRequire(pair != NULL, "create paired Bridge");
    ((bridge_tstate_t *) tunnelGetState(f.node))->pair_tun = pair;
    ((bridge_tstate_t *) tunnelGetState(pair))->pair_tun   = f.node;
    pair->prev                                             = f.prev;
    pair->next                                             = f.next;
    sbuf_t *buf                                            = easyPayload(splice);
    easyExpect(&f, buf, "prebody", 7, 3);
    bridgeTunnelUpStreamPayload(f.node, f.line, buf);
    easyRequire(f.expected == NULL && f.downstream == 1 && f.upstream == 0,
                "Bridge upstream must map to paired downstream");
    buf = easyPayload(splice);
    easyExpect(&f, buf, "prebody", 7, 3);
    bridgeTunnelDownStreamPayload(pair, f.line, buf);
    easyRequire(f.expected == NULL && f.upstream == 1, "Bridge downstream must map to paired upstream");
    tunnelDestroy(pair);
    easyTeardown(&f);

    for (unsigned active = 0; active < 2; ++active)
    {
        node_t node             = nodeBlackHoleGet();
        node.node_settings_json = cJSON_Parse(active ? "{\"mode\":\"active\"}" : "{\"mode\":\"passive\"}");
        easySetup(&f, node.createHandle(&node));
        f.node->next = NULL;
        f.node->fnInitU(f.node, f.line);
        if (active)
            easyRequire(f.line == NULL && f.finishes == 1, "active sink must close during Init");
        else
        {
            easyRequire(f.established == 1, "passive sink must establish");
            buf = easyPayload(splice);
            easyWatch(buf);
            f.node->fnPayloadU(f.node, f.line, buf);
            easyRequireDisposed();
            f.node->fnFinU(f.node, f.line);
            easyRequire(lineIsAlive(f.line) && f.finishes == 0, "passive sink must borrow its line");
        }
        easyTeardown(&f);
        cJSON_Delete(node.node_settings_json);
        memoryFree(node.type);
    }
}
