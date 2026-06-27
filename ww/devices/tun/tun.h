#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define TUN_LOG_EVERYTHING false

enum
{
    kTunDeviceMaxDnsServers = 2
};

typedef struct sbuf_s       sbuf_t;
typedef struct tun_device_s tun_device_t;

typedef void (*TunReadEventHandle)(tun_device_t *tdev, void *userdata, sbuf_t *buf, uint8_t wid);

typedef struct tun_default_route_s
{
    bool     have_v4;
    uint32_t ifindex_v4;
    bool     have_v6;
    uint32_t ifindex_v6;
    char     ifname[64];
} tun_default_route_t;

tun_device_t *tundeviceCreate(const char *name, bool offload, uint16_t mtu, void *userdata, TunReadEventHandle cb);
void          tundeviceDestroy(tun_device_t *tdev);
bool          tundeviceBringUp(tun_device_t *tdev);
bool          tundeviceBringDown(tun_device_t *tdev);
bool          tundeviceIsUp(const tun_device_t *tdev);
bool          tundeviceAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool          tundeviceUnAssignIP(tun_device_t *tdev, const char *ip_presentation, unsigned int subnet);
bool          tundeviceSetDnsServers(tun_device_t *tdev, const char *const *servers, size_t count);
bool          tundeviceClearDnsServers(tun_device_t *tdev);
bool          tundeviceAddRoute(tun_device_t *tdev, const char *cidr, const char *route_table);
bool          tundeviceRemoveRoute(tun_device_t *tdev, const char *cidr, const char *route_table);
bool          tundeviceWrite(tun_device_t *tdev, sbuf_t *buf);
bool          tundeviceDetectDefaultInterface(tun_default_route_t *out);
bool          tundeviceDisableReversePathFiltering(const char *ifname);

// Retrieves the OS interface LUID value of the device (Windows NET_LUID.Value).
// Returns false on platforms that have no such identifier; *out is set to 0 then.
bool tundeviceGetLuid(tun_device_t *tdev, uint64_t *out);
