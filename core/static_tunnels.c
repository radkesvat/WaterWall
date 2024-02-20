#include "ww.h"
#include "library_loader.h"
#include "loggers/core_logger.h"

#ifdef INCLUDE_TCP_LISTENER
#include "tunnels/adapters/tcp_listener/tcp_listener.h"
#endif

#define USING(x)                                                       \
    do                                                                 \
    {                                                                  \
        registerStaticLib((tunnel_lib_t){new##x, api##x, destroy##x}); \
        LOGD("Imported static tunnel lib%s.a", #x);                    \
    } while (0)

void loadStaticTunnelsIntoCore()
{
#ifdef INCLUDE_TCP_LISTENER
    USING(TcpListener);
#endif
}