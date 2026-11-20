#include <steam/steamnetworkingtypes.h>

namespace SteamNetworkingSocketsLib
{
// Native diagnostic emitter in the pinned GNS static library.
void ReallySpewTypeFmt(int type, const char *format, ...);
} // namespace SteamNetworkingSocketsLib

extern "C" void gnsTestEmitNativeDiagnostics(void)
{
    SteamNetworkingSocketsLib::ReallySpewTypeFmt(k_ESteamNetworkingSocketsDebugOutputType_Warning,
                                                 "native GNS fixture warning");
    SteamNetworkingSocketsLib::ReallySpewTypeFmt(k_ESteamNetworkingSocketsDebugOutputType_Error,
                                                 "native GNS fixture error");
}
