#include "library_loader.h"
#include <string.h>
#include "hv/hplatform.h"


#define i_key tunnel_lib_t
#define i_type vec_static_libs
#include "stc/vec.h"

static struct
{
    const char *search_path;
    vec_static_libs slibs;
} *state;

static tunnel_lib_t dynLoadTunnelLib(const char *name)
{
}

tunnel_lib_t loadTunnelLib(const char *name)
{

    if (state != NULL)
    {
        //fech statics
    }
    // CHECKFOR(TcpListener);

    return dynLoadTunnelLib(name);
}

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
