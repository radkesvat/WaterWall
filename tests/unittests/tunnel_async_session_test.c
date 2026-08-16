#include "net/tunnel_async_session.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "tunnel async-session test failed: %s\n", message);
        exit(1);
    }
}

int main(void)
{
    tunnel_t  fake_tunnel = {0};
    tunnel_t *observed    = NULL;

    tunnel_async_session_t *session = tunnelasyncsessionCreate(&fake_tunnel, "unit-test");
    require(session != NULL, "create returned NULL");
    require(! tunnelasyncsessionEnter(session, &observed), "a closed session admitted entry");
    require(tunnelasyncsessionOpen(session), "first open failed");
    require(tunnelasyncsessionIsAccepting(session), "an open session did not report admission");
    require(tunnelasyncsessionEnter(session, &observed), "open session rejected entry");
    require(observed == &fake_tunnel, "entry published the wrong tunnel");

    tunnelasyncsessionDetach(session);
    observed = (tunnel_t *) (uintptr_t) 1;
    require(! tunnelasyncsessionEnter(session, &observed), "detached session admitted a new entry");
    require(observed == (tunnel_t *) (uintptr_t) 1, "failed entry modified its output");
    tunnelasyncsessionLeave(session);
    tunnelasyncsessionCloseAndQuiesce(session);

    /* Detach is intentionally idempotent during staged/repeated owner cleanup. */
    tunnelasyncsessionDetach(session);
    require(! tunnelasyncsessionEnter(session, &observed), "double detach republished the tunnel");

    /* A queued callback may keep the session allocation alive past detach. */
    tunnelasyncsessionRef(session);
    tunnelasyncsessionUnref(session);

    tunnelasyncsessionUnref(session);

    puts("tunnel async-session tests passed");
    return 0;
}
