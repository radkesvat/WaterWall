#include "ww.h"
#include "library_loader.h"

#define USING(x) registerStaticLib((tunnel_lib_t){new##x, api##x, destroy##x})

void loadStaticTunnelsIntoCore()
{
    USING(TcpListener);
}