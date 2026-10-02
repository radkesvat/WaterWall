/*
 * Covers: Uses synchronous fake neighbors to verify server/fatal Payload-before-Finish ordering, no
 * reflection toward a finished side, raw-Finish behavior, Reality-owned cleanup after line death during
 * final Payload, and fatal no-response/dominance behavior. Every record profile covers fragmented and
 * coalesced alerts. A client consumes server `close_notify` without replying and immediately closes both
 * sides even when the fake peer supplies no FIN. Generic first-alert authorization uses a fatal record;
 * Pending/Visitor/destination teardown remains free of synthetic alerts. The same fixture injects `1`,
 * `16383`, `16384`, `16385`, `32768`, and `32769` byte callbacks through both real send helpers for
 * every profile, decrypts/reassembles every record, checks exact native body lengths, and proves
 * re-entrant line death stops a multi-record send after the transferred record. A real BoringSSL TLS 1.3
 * client Finished fixture verifies that the one-shot pre-request cover allowance is initialized only
 * after TLS 1.3 key derivation, consumed before re-entrant destination forwarding, never reset, and
 * leaves the minimum configured sniffing budget available for later failed candidates; TLS 1.2
 * accounting remains unchanged.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Exact return/byte/order and resource-count oracles in the explicit case bodies.
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.reality_close_lifecycle_unit
 */
#include "reality_close_lifecycle_test.h"
#include "wwapi.h"

#include "wcrypto.h"

int main(void)
{
    if (! globalstateInitializeSecureRandom())
    {
        fprintf(stderr, "FAIL: secure random initialization failed\n");
        return 1;
    }
    if (! frandGlobalInit())
    {
        fprintf(stderr, "FAIL: fast random initialization failed\n");
        globalstateDestroySecureRandom();
        return 1;
    }
    frandInit();
    if (wCryptoGlobalInit() != kWCryptoOk)
    {
        fprintf(stderr, "FAIL: crypto global initialization failed\n");
        frandThreadCleanup();
        frandGlobalCleanup();
        globalstateDestroySecureRandom();
        return 1;
    }
    realityTestClientCloseLifecycle();
    realityTestServerCloseLifecycle();
    realityTestClientRecordSizing();
    realityTestServerRecordSizing();
    wCryptoGlobalCleanup();
    frandThreadCleanup();
    frandGlobalCleanup();
    globalstateDestroySecureRandom();
    return 0;
}
