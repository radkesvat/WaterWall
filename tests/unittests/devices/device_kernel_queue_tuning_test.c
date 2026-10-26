/*
 * Covers startup kernel queue sizing across every RAM profile and actual queue
 * counts, explicit targets, disabled tuning, and automatic aggregate ceilings.
 * Native syscall refusal/readback belongs to the TUN/Capture device fixtures.
 * CTest: waterwall.device_kernel_queue_tuning_unit
 */
#include "devices/device_kernel_queue_tuning.h"
#include "test_assert.h"

#include <limits.h>
#include <stdio.h>

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static void testAutomaticTargets(void)
{
    const uint32_t counts[] = {1, 4, 16, 32, 64, 254};
    const struct
    {
        uint32_t profile;
        uint32_t tun[6];
        uint32_t capture[6];
        uint32_t receive[6];
    } cases[] = {
        {kRamProfileS1Memory,
         {1024, 1024, 1024, 1024, 1024, 516},
         {65536, 16384, 4096, 2048, 1024, 516},
         {67108864, 16777216, 4194304, 2097152, 1048576, 528416}},
        {kRamProfileS2Memory,
         {1024, 1024, 1024, 1024, 1024, 516},
         {65536, 16384, 4096, 2048, 1024, 516},
         {67108864, 16777216, 4194304, 2097152, 1048576, 528416}},
        {kRamProfileM1Memory,
         {2048, 2048, 2048, 2048, 2048, 516},
         {65536, 16384, 4096, 2048, 2048, 516},
         {67108864, 16777216, 4194304, 2097152, 2097152, 528416}},
        {kRamProfileM2Memory,
         {4096, 4096, 4096, 4096, 2048, 516},
         {65536, 16384, 4096, 2048, 2048, 516},
         {67108864, 16777216, 4194304, 2097152, 2097152, 528416}},
        {kRamProfileL1Memory,
         {8192, 8192, 8192, 4096, 2048, 516},
         {65536, 16384, 4096, 4096, 2048, 516},
         {67108864, 16777216, 4194304, 4194304, 2097152, 528416}},
        {kRamProfileL2Memory,
         {8192, 8192, 8192, 4096, 2048, 516},
         {65536, 16384, 4096, 4096, 2048, 516},
         {67108864, 16777216, 4194304, 4194304, 2097152, 528416}},
    };
    for (size_t p = 0; p < sizeof(cases) / sizeof(cases[0]); ++p)
    {
        for (size_t q = 0; q < sizeof(counts) / sizeof(counts[0]); ++q)
        {
            require(deviceKernelQueueTunTarget(cases[p].profile, counts[q], 0) == cases[p].tun[q],
                    "TUN automatic target does not match profile and actual queue count");
            require(deviceKernelQueueCapturePackets(cases[p].profile, counts[q], 0, true) == cases[p].capture[q],
                    "NFQUEUE automatic target does not match bounded per-queue headroom");
            require(deviceKernelQueueCaptureReceiveBytes(cases[p].profile, counts[q], 0, true) == cases[p].receive[q],
                    "Netlink automatic request does not match bounded per-socket headroom");
        }
        for (uint32_t queues = 1; queues <= 254; ++queues)
        {
            require(deviceKernelQueueTunTarget(cases[p].profile, queues, 0) * queues <= 131072,
                    "TUN automatic target exceeded its aggregate ceiling");
            require(deviceKernelQueueCapturePackets(cases[p].profile, queues, 0, true) * queues <= 131072,
                    "NFQUEUE automatic target exceeded its aggregate ceiling");
            require(deviceKernelQueueCaptureReceiveBytes(cases[p].profile, queues, 0, true) * queues <= 134217728,
                    "Netlink automatic request exceeded its aggregate ceiling");
        }
    }
}

static void testExplicitAndDisabledTargets(void)
{
    require(deviceKernelQueueTunTarget(kRamProfileS1Memory, 64, 16384) == 16384,
            "explicit TUN target was treated as a total or limited by automatic sizing");
    require(deviceKernelQueueCapturePackets(kRamProfileS1Memory, 4, 262144, true) == 65536,
            "explicit NFQUEUE total was not divided by the actual queue count");
    require(deviceKernelQueueCaptureReceiveBytes(kRamProfileS1Memory, 4, 268435456, true) == 67108864,
            "explicit Netlink request total was not divided by actual queue count");
    require(deviceKernelQueueCapturePackets(kRamProfileL2Memory, 32, 1, true) == 2048,
            "small explicit NFQUEUE target reduced baseline capacity");
    require(deviceKernelQueueCaptureReceiveBytes(kRamProfileL2Memory, 32, 1, true) == 2097152,
            "small explicit Netlink target reduced baseline capacity");
    require(deviceKernelQueueCapturePackets(kRamProfileL2Memory, 32, INT_MAX, false) == 2048,
            "disabled NFQUEUE tuning applied an override");
    require(deviceKernelQueueCaptureReceiveBytes(kRamProfileL2Memory, 32, INT_MAX, false) == 2097152,
            "disabled Netlink tuning applied an override");
    require(deviceKernelQueueTunTarget(kRamProfileL2Memory, 1, INT_MAX) == INT_MAX,
            "maximum TUN override was truncated");
    require(deviceKernelQueueCaptureReceiveBytes(kRamProfileL2Memory, 1, INT_MAX, true) == INT_MAX,
            "maximum Netlink override overflowed");
}

int main(void)
{
    TEST_RUN_CASE(testAutomaticTargets);
    TEST_RUN_CASE(testExplicitAndDisabledTargets);
    puts("device kernel queue tuning policy tests passed");
    return 0;
}
