#include "library_loader.h"
#include "ww.h"
#include "basic_types.h"
#include "loggers/core_logger.h" //NOLINT
#include "stc/common.h"
#include "utils/hashutils.h"
#include "hplatform.h"
#include <stdlib.h> 
#include <string.h>

#define i_key  tunnel_lib_t    // NOLINT
#define i_type vec_static_libs // NOLINT
#include "stc/vec.h"

static struct
{
    const char     *search_path;
    vec_static_libs slibs;
} *state;


// #ifdef OS_WIN
// #include <windows.h> // for Windows LoadLibrary/GetProcAddress
// #else
// #include <dlfcn.h>  // for POSIX dlopen/dlsym
// #endif

// void *getSymbol(void *libHandle, const char *name) {
//     #ifdef OS_WIN
//     return GetProcAddress((HMODULE)libHandle, name);
//     #else
//     return dlsym(libHandle, name);
//     #endif
// }

// static tunnel_lib_t dynLoadTunnelLib(hash_t hname) {
//     char libName[256];
//     snprintf(libName, sizeof(libName), "libname-%u.so", hname); // Example library name generation

//     void *handle = NULL;
//     #ifdef OS_WIN
//     handle = LoadLibrary(libName);
//     #else
//     handle = dlopen(libName, RTLD_LAZY);
//     #endif

//     if (!handle) {
//         LOGF("Failed to load library: %s", libName);
//         return (tunnel_lib_t){0};
//     }

//     tunnel_lib_t lib = {0};
//     lib.createHandle = (struct tunnel_s *(*)(node_instance_context_t *))getSymbol(handle, "createHandle");
//     lib.destroyHandle = (struct tunnel_s *(*)(struct tunnel_s *))getSymbol(handle, "destroyHandle");
//     lib.apiHandle = (api_result_t (*)(struct tunnel_s *, const char *))getSymbol(handle, "apiHandle");
//     lib.getMetadataHandle = (tunnel_metadata_t (*)(void))getSymbol(handle, "getMetadataHandle");
//     lib.hash_name = hname;

//     return lib;
// }



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


void registerStaticLib(tunnel_lib_t lib)
{
    if (state == NULL)
    {
        state = globalMalloc(sizeof(*state));
        memset(state, 0, sizeof(*state));
        state->slibs = vec_static_libs_init();
    }

    vec_static_libs_push(&(state->slibs), lib);
}
