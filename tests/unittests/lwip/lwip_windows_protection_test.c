/* Exercise a real pooled allocation inside nested Win32 lwIP protection and
 * verify that the inner release keeps the critical section owned.
 * CTest: waterwall.lwip_windows_protection_unit */
#include "wdef.h"

#include "capacity_internal.h"
#include "lwip/mem.h"
#include "lwip/memp.h"
#include "lwip/sys.h"
#include "test_assert.h"
#include <windows.h>

/* NO_SYS omits the port initialization declaration from sys.h. */
void sys_init(void);
void wwLwipPortCleanup(void);

/* Probe the port's native lock from a different thread without a timing race. */
extern CRITICAL_SECTION critSec;

#define require(condition, message) TEST_REQUIRE(TEST_FAILURE_EXIT, condition, message)

static DWORD WINAPI contendForProtection(void *checked)
{
    require(! TryEnterCriticalSection(&critSec), "inner release exposed the outer protected scope");
    require(SetEvent((HANDLE) checked), "could not report the lock probe");

    const sys_prot_t level = sys_arch_protect();
    sys_arch_unprotect(level);
    return 0;
}

int main(void)
{
    testCaseSet("nested Win32 lwIP protection");
    sys_init();
    wwLwipCapacityInitialize();
    mem_init();
    memp_init();

    const sys_prot_t outer      = sys_arch_protect();
    const sys_prot_t inner      = sys_arch_protect();
    void            *allocation = mem_malloc(1460);
    require(allocation != NULL, "pooled allocation failed inside nested protection");
    mem_free(allocation);
    sys_arch_unprotect(inner);

    HANDLE checked = CreateEventW(NULL, FALSE, FALSE, NULL);
    require(checked != NULL, "could not create the lock probe event");
    HANDLE thread = CreateThread(NULL, 0, contendForProtection, checked, 0, NULL);
    require(thread != NULL, "could not create the contending thread");
    require(WaitForSingleObject(checked, 5000) == WAIT_OBJECT_0, "contending thread did not check the lock");
    sys_arch_unprotect(outer);
    require(WaitForSingleObject(thread, 5000) == WAIT_OBJECT_0,
            "contending thread could not acquire the released lock");
    CloseHandle(thread);
    CloseHandle(checked);

    wwLwipCapacityCleanup();
    wwLwipPortCleanup();
    return 0;
}
