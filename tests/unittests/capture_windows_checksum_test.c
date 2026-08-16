#include "wwapi.h"

#include "devices/capture/capture_windows_checksum.h"

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

/*
 * The full capture-metadata provenance matrix.
 *
 * The sixth is WinDivert's Impostor bit. Outbound and loopback packets are the
 * local stack's own, so a cleared checksum-valid bit on one means offload the
 * stack had not applied yet, which this reader may finish. An impostor came from
 * another injecting driver and promised nothing, so the same cleared bit must
 * not license materializing a checksum over its bytes.
 */
int main(void)
{
    bool saw_impostor_downgrade = false;

    for (unsigned int mask = 0; mask < 64; ++mask)
    {
        const bool ip_valid  = (mask & 1U) != 0;
        const bool tcp_valid = (mask & 2U) != 0;
        const bool udp_valid = (mask & 4U) != 0;
        const bool outbound  = (mask & 8U) != 0;
        const bool loopback  = (mask & 16U) != 0;
        const bool impostor  = (mask & 32U) != 0;
        const bool trusted   = (outbound || loopback) && ! impostor;

        const device_packet_checksum_provenance_t provenance =
            captureWindowsChecksumProvenance(ip_valid, tcp_valid, udp_valid, outbound, loopback, impostor);
        require(provenance.ipv4 == captureWindowsChecksumField(ip_valid, trusted),
                "WinDivert IPv4 checksum provenance ignored its independent flag");
        require(provenance.tcp == captureWindowsChecksumField(tcp_valid, trusted),
                "WinDivert TCP checksum provenance ignored its independent flag");
        require(provenance.udp == captureWindowsChecksumField(udp_valid, trusted),
                "WinDivert UDP checksum provenance ignored its independent flag");

        if (impostor && (outbound || loopback) && ! ip_valid)
        {
            require(provenance.ipv4 == kDeviceIpv4ChecksumUntrusted,
                    "an impostor's outbound/loopback packet was treated as pending stack offload");
            saw_impostor_downgrade = true;
        }
    }

    require(saw_impostor_downgrade, "the matrix never reached an impostor outbound/loopback case");
    puts("Capture Windows checksum provenance tests passed");
    return 0;
}
