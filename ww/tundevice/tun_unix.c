#include "tun.h"
#include "ww.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include "hchan.h"















tun_device_t *createTunDevice(hloop_t *loop, const char *name, bool offload)
{
    (void) offload; // todo (send/receive offloading)

    struct ifreq ifr;

    int fd = open("/dev/net/tun", O_RDWR);
    if (fd < 0)
    {
        perror("Opening /dev/net/tun");
        return NULL;
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN | IFF_NO_PI; // TUN device, no packet information
    if (*name)
    {
        strncpy(ifr.ifr_name, name, IFNAMSIZ);
    }

    int err = ioctl(fd, TUNSETIFF, (void *) &ifr);
    if (err < 0)
    {
        perror("ioctl(TUNSETIFF)");
        close(fd);
        return NULL;
    }

    tun_device_t *tdev = globalMalloc(sizeof(tun_device_t));
    *tdev = (tun_device_t) {.name = strdup(ifr.ifr_name), .handle = fd, .io = hio_get(loop, fd)};

    return tdev;
}

