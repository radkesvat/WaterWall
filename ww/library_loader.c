#include "library_loader.h"
#include "hplatform.h"
#include "loggers/core_logger.h"
#include <string.h>

#define i_key  tunnel_lib_t    // NOLINT
#define i_type vec_static_libs // NOLINT
#include "stc/vec.h"

static struct
{
    const char     *search_path;
    vec_static_libs slibs;
} *state;

static tunnel_lib_t dynLoadTunnelLib(hash_t hname)
{
    (void) hname;
    LOGF("dynLoadTunnelLib not implemented");
    return (tunnel_lib_t){0};
}

tunnel_lib_t loadTunnelLibByHash(hash_t hname)
{

    if (state != NULL)
    {
        c_foreach(k, vec_static_libs, state->slibs)
        {
            if ((k.ref)->hash_name == hname)
            {
                return *(k.ref);
            }
        }
    }
    return dynLoadTunnelLib(hname);
}
tunnel_lib_t loadTunnelLib(const char *name)
{
    hash_t hname = CALC_HASH_BYTES(name, strlen(name));
    return loadTunnelLibByHash(hname);
}

// CHECKFOR(TcpListener);

void registerStaticLib(tunnel_lib_t lib)
{
    if (state == NULL)
    {
        state = malloc(sizeof(*state));
        memset(state, 0, sizeof(*state));
        state->slibs = vec_static_libs_init();
    }

    vec_static_libs_push(&(state->slibs), lib);
}
