#include "UserController/structure.h"
#include "easy_nodes_splice_fixture.h"

static uint64_t upload, download;
static unsigned account_calls, releases;
static bool     reject;
bool __wrap_authenticationclientUserAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t up, uint64_t down,
                                                   uint64_t now);
void __wrap_authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle,
                                                      const user_ip_key_t *ip);
bool __wrap_authenticationclientUserAccountTraffic(tunnel_t *t, const user_handle_t *handle, uint64_t up, uint64_t down,
                                                   uint64_t now)
{
    discard t;
    discard handle;
    discard now;
    upload += up;
    download += down;
    ++account_calls;
    return reject;
}
void __wrap_authenticationclientUserReleaseConnection(tunnel_t *t, const user_handle_t *handle, const user_ip_key_t *ip)
{
    discard t;
    discard handle;
    discard ip;
    ++releases;
}
void testUserControllerSplice(bool splice)
{
    for (unsigned reverse = 0; reverse < 2; ++reverse)
    {
        for (unsigned managed = 0; managed < 2; ++managed)
        {
            easy_fixture_t f;
            easySetup(&f, tunnelCreate(NULL, sizeof(usercontroller_tstate_t), sizeof(usercontroller_lstate_t)));
            usercontroller_lstate_t *ls = lineGetState(f.line, f.node);
            usercontrollerLinestateInitialize(ls, reverse);
            ls->managed = managed;
            upload = download = account_calls = releases = 0;
            reject                                       = false;
            sbuf_t *buf                                  = easyPayload(splice);
            easyExpect(&f, buf, "prebody", 7, 3);
            usercontrollerTunnelUpStreamPayload(f.node, f.line, buf);
            easyRequire(f.expected == NULL && f.upstream == 1, "user upstream forwarding");
            easyRequire(upload == (managed && ! reverse ? 7 : 0) && download == (managed && reverse ? 7 : 0),
                        "upstream logical accounting");
            buf = easyPayload(splice);
            easyExpect(&f, buf, "prebody", 7, 3);
            usercontrollerTunnelDownStreamPayload(f.node, f.line, buf);
            easyRequire(f.expected == NULL && f.downstream == 1, "user downstream forwarding");
            easyRequire(upload == (managed ? 7 : 0) && download == (managed ? 7 : 0) && account_calls == managed * 2,
                        "downstream logical accounting");
            if (managed)
            {
                reject = true;
                buf    = easyPayload(splice);
                easyWatch(buf);
                if (reverse)
                    usercontrollerTunnelDownStreamPayload(f.node, f.line, buf);
                else
                    usercontrollerTunnelUpStreamPayload(f.node, f.line, buf);
                easyRequireDisposed();
                easyRequire(f.line == NULL && f.finishes == 2 && releases == 1,
                            "rejection must dispose then close/release once");
            }
            easyTeardown(&f);
        }
    }
}
