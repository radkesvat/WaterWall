/*
 * Covers: capture windows checksum; the explicit inputs, callbacks and expected results below define
 * this suite.
 * Setup: The included implementation/API and the deterministic inputs shown below; no integration
 * topology is implied.
 * Checks: Assertion labels include: capture_windows_checksum_test; WinDivert IPv4 checksum provenance
 * ignored its independent flag; WinDivert TCP checksum provenance ignored its independent flag;
 * WinDivert UDP checksum provenance ignored its independent flag
 * Limits: Platform/feature branches remain conditional. Component fixtures do not establish host-network
 * or application-throughput behavior.
 * CTest: waterwall.capture_windows_checksum_unit
 */
#include "wwapi.h"

#include "test_assert.h"

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

#include "devices/capture/capture_windows_checksum.h"


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
    testCaseSet("capture_windows_checksum_test");
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
