#include "wconfig.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define WATERWALL_STRINGIFY_INNER(x) #x
#define WATERWALL_STRINGIFY(x)       WATERWALL_STRINGIFY_INNER(x)

int waterwallInnerMain(int argc, char **argv);

#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    #define WATERWALL_STARTUP_X86_64 1
#else
    #define WATERWALL_STARTUP_X86_64 0
#endif

#if WATERWALL_STARTUP_X86_64 && WW_HAVE_ADVANCED_CPU_INSTRUCTIONS

enum
{
    kCpuSse3Bit    = 1u << 0,
    kCpuSsse3Bit   = 1u << 9,
    kCpuFmaBit     = 1u << 12,
    kCpuSse41Bit   = 1u << 19,
    kCpuSse42Bit   = 1u << 20,
    kCpuMovbeBit   = 1u << 22,
    kCpuPopcntBit  = 1u << 23,
    kCpuXsaveBit   = 1u << 26,
    kCpuOsxsaveBit = 1u << 27,
    kCpuAvxBit     = 1u << 28,
    kCpuF16cBit    = 1u << 29,
    kCpuBmi1Bit    = 1u << 3,
    kCpuAvx2Bit    = 1u << 5,
    kCpuBmi2Bit    = 1u << 8,
    kCpuAvx512fBit = 1u << 16,
    kCpuLzcntBit   = 1u << 5
};

typedef struct startup_cpu_regs_s
{
    uint32_t eax;
    uint32_t ebx;
    uint32_t ecx;
    uint32_t edx;
} startup_cpu_regs_t;

    #if defined(_MSC_VER)
        #include <intrin.h>

static bool startupCpuId(uint32_t leaf, uint32_t subleaf, startup_cpu_regs_t *out)
{
    int regs[4];
    __cpuidex(regs, (int) leaf, (int) subleaf);
    out->eax = (uint32_t) regs[0];
    out->ebx = (uint32_t) regs[1];
    out->ecx = (uint32_t) regs[2];
    out->edx = (uint32_t) regs[3];
    return true;
}

static uint64_t startupXgetbv0(void)
{
    return _xgetbv(0);
}

    #else
        #include <cpuid.h>

static bool startupCpuId(uint32_t leaf, uint32_t subleaf, startup_cpu_regs_t *out)
{
    uint32_t max_leaf;
    if (leaf >= 0x80000000u)
    {
        max_leaf = __get_cpuid_max(0x80000000u, NULL);
    }
    else
    {
        max_leaf = __get_cpuid_max(0, NULL);
    }
    if (max_leaf < leaf)
    {
        return false;
    }

    __cpuid_count(leaf, subleaf, out->eax, out->ebx, out->ecx, out->edx);
    return true;
}

static uint64_t startupXgetbv0(void)
{
    uint32_t eax;
    uint32_t edx;
    __asm__ volatile("xgetbv" : "=a"(eax), "=d"(edx) : "c"(0));
    return ((uint64_t) edx << 32) | eax;
}
    #endif

static bool startupCpuHasAvxOsSupport(const startup_cpu_regs_t *leaf1)
{
    if ((leaf1->ecx & (kCpuXsaveBit | kCpuOsxsaveBit | kCpuAvxBit)) !=
        (kCpuXsaveBit | kCpuOsxsaveBit | kCpuAvxBit))
    {
        return false;
    }

    return (startupXgetbv0() & 0x6u) == 0x6u;
}

static bool startupCpuHasAvx512OsSupport(const startup_cpu_regs_t *leaf1)
{
    if ((leaf1->ecx & (kCpuXsaveBit | kCpuOsxsaveBit | kCpuAvxBit)) !=
        (kCpuXsaveBit | kCpuOsxsaveBit | kCpuAvxBit))
    {
        return false;
    }

    return (startupXgetbv0() & 0xe6u) == 0xe6u;
}

static bool startupCpuSupportsConfiguredBuild(void)
{
    startup_cpu_regs_t leaf1;

    if (! startupCpuId(1, 0, &leaf1))
    {
        return false;
    }

#if HAVE_AVX
    /* Only AVX (and the AVX2/AVX512 paths layered on it) require OS XSAVE/YMM support. An
     * SSE3-only build (e.g. the x64 old-cpu build) must not demand AVX from a pre-AVX CPU. */
    if (! startupCpuHasAvxOsSupport(&leaf1))
    {
        return false;
    }
#endif

#if HAVE_SSE3
    if ((leaf1.ecx & kCpuSse3Bit) == 0)
    {
        return false;
    }
#endif

#if HAVE_AVX2 || ENABLE_MEMCOPY_AVX512
    startup_cpu_regs_t leaf7;

    if (! startupCpuId(7, 0, &leaf7))
    {
        return false;
    }
#endif

#if HAVE_AVX2
    startup_cpu_regs_t ext1;

    if (! startupCpuId(0x80000001u, 0, &ext1))
    {
        return false;
    }

    if ((leaf1.ecx & (kCpuSse3Bit | kCpuSsse3Bit | kCpuFmaBit | kCpuSse41Bit | kCpuSse42Bit | kCpuMovbeBit |
                      kCpuPopcntBit | kCpuAvxBit | kCpuF16cBit)) !=
        (kCpuSse3Bit | kCpuSsse3Bit | kCpuFmaBit | kCpuSse41Bit | kCpuSse42Bit | kCpuMovbeBit | kCpuPopcntBit |
         kCpuAvxBit | kCpuF16cBit))
    {
        return false;
    }

    if ((leaf7.ebx & (kCpuBmi1Bit | kCpuAvx2Bit | kCpuBmi2Bit)) != (kCpuBmi1Bit | kCpuAvx2Bit | kCpuBmi2Bit))
    {
        return false;
    }

    if ((ext1.ecx & kCpuLzcntBit) == 0)
    {
        return false;
    }
#endif

#if ENABLE_MEMCOPY_AVX512
    if (! startupCpuHasAvx512OsSupport(&leaf1) || (leaf7.ebx & kCpuAvx512fBit) == 0)
    {
        return false;
    }
#endif

    return true;
}

#else
static bool startupCpuSupportsConfiguredBuild(void)
{
    return true;
}
#endif

static void startupPrintUnsupportedCpu(void)
{
    fprintf(stderr,
            "Waterwall version %s\n"
            "This Waterwall binary was built for a newer x86-64 CPU than this machine/OS exposes.\n"
            "Use the x64 old-cpu build (SSE3 baseline, no AVX/AVX2) for CPUs without AVX2 support, or\n"
            "rebuild with advanced CPU instructions disabled for CPUs without SSE3.\n",
            WATERWALL_STRINGIFY(WATERWALL_VERSION));
}

int main(int argc, char **argv)
{
    if (! startupCpuSupportsConfiguredBuild())
    {
        startupPrintUnsupportedCpu();
        return 1;
    }

    return waterwallInnerMain(argc, argv);
}
