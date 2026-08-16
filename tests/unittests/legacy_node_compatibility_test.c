#include "wwapi.h"

#include "lifecycle_node_abi_fixture.h"
#include "managers/node_manager.h"
#include "node_builder/node_library.h"

#ifdef OS_WIN
#include <windows.h>
#else
#include <dlfcn.h>
#include <pthread.h>
#include <unistd.h>
#endif

#ifndef MISSING_NODE_LIBRARY_PATH
#error "MISSING_NODE_LIBRARY_PATH is required"
#endif
#ifndef MISMATCHED_NODE_LIBRARY_PATH
#error "MISMATCHED_NODE_LIBRARY_PATH is required"
#endif
#ifndef LIFECYCLE_V2_NODE_LIBRARY_PATH
#error "LIFECYCLE_V2_NODE_LIBRARY_PATH is required"
#endif

typedef void (*RejectedResetCounters)(void);
typedef unsigned int (*RejectedGetGetterCalls)(void);
typedef void (*LifecycleReset)(void);
typedef void (*LifecycleSetAllocator)(void *(*) (size_t) );
typedef void (*LifecycleGetSnapshot)(lifecycle_node_fixture_snapshot_t *);

typedef struct worker_stage_driver_s
{
    tunnel_t                     *tunnel;
    const ww_lifecycle_context_t *context;
    wcond_mutex_t                 condition_mutex;
    wcondvar_t                    condition;
    unsigned int                  command;
    unsigned int                  completed;
} worker_stage_driver_t;

static void require(bool condition, const char *message)
{
    if (! condition)
    {
        fprintf(stderr, "FAIL: %s\n", message);
        exit(1);
    }
}

static bool copyFile(const char *source, const char *destination)
{
    FILE *input = fopen(source, "rb");
    if (input == NULL)
    {
        return false;
    }
    FILE *output = fopen(destination, "wb");
    if (output == NULL)
    {
        fclose(input);
        return false;
    }

    bool    ok = true;
    uint8_t block[16384];
    for (;;)
    {
        size_t count = fread(block, 1, sizeof(block), input);
        if (count != 0 && fwrite(block, 1, count, output) != count)
        {
            ok = false;
            break;
        }
        if (count != sizeof(block))
        {
            ok = ! ferror(input);
            break;
        }
    }
    ok = fclose(output) == 0 && ok;
    fclose(input);
    return ok;
}

static const char *libraryExtension(void)
{
#ifdef OS_WIN
    return ".dll";
#elif defined(OS_APPLE)
    return ".dylib";
#else
    return ".so";
#endif
}

static void libraryDirectory(const char *source, char *directory, size_t directory_size)
{
    const char *slash = strrchr(source, '/');
#ifdef OS_WIN
    const char *backslash = strrchr(source, '\\');
    if (backslash != NULL && (slash == NULL || backslash > slash))
    {
        slash = backslash;
    }
#endif
    require(slash != NULL, "fixture library path has no directory");
    const size_t length = (size_t) (slash - source);
    require(length < directory_size, "fixture library directory is too long");
    memoryCopy(directory, source, length);
    directory[length] = '\0';
}

static void stageCandidate(const char *source, const char *directory, const char *type, char *candidate,
                           size_t candidate_size)
{
    const hash_t hash   = calcHashBytes(type, strlen(type));
    const int    length = snprintf(
        candidate, candidate_size, "%s/ww-node-%016llx%s", directory, (unsigned long long) hash, libraryExtension());
    require(length > 0 && (size_t) length < candidate_size, "fixture candidate path is too long");
    require(copyFile(source, candidate), "failed to stage node fixture library");
}

static void *openLibrary(const char *path)
{
#ifdef OS_WIN
    return (void *) LoadLibraryA(path);
#else
    return dlopen(path, RTLD_NOW | RTLD_LOCAL);
#endif
}

static void closeLibrary(void *handle)
{
#ifdef OS_WIN
    FreeLibrary((HMODULE) handle);
#else
    dlclose(handle);
#endif
}

static void deleteLibrary(const char *path)
{
#ifdef OS_WIN
    DeleteFileA(path);
#else
    unlink(path);
#endif
}

static void loadSymbol(void *handle, const char *name, void *out, size_t size)
{
#ifdef OS_WIN
    FARPROC symbol = GetProcAddress((HMODULE) handle, name);
#else
    void *symbol = dlsym(handle, name);
#endif
    require(symbol != NULL, "fixture witness symbol is missing");
    memoryCopy(out, &symbol, size);
}

static void verifyRejectedLibrary(const char *path, const char *directory, const char *type)
{
    char candidate[MAX_PATH];
    stageCandidate(path, directory, type, candidate, sizeof(candidate));
    void *handle = openLibrary(candidate);
    require(handle != NULL, "failed to open rejected node fixture");

    RejectedResetCounters  reset     = NULL;
    RejectedGetGetterCalls get_calls = NULL;
    loadSymbol(handle, "rejectedNodeResetCounters", &reset, sizeof(reset));
    loadSymbol(handle, "rejectedNodeGetGetterCalls", &get_calls, sizeof(get_calls));
    reset();

    node_t node = nodelibraryLoadByTypeName(type);
    require(node.createHandle == NULL, "incompatible lifecycle ABI was accepted");
    require(get_calls() == 0, "node getter ran before lifecycle ABI rejection");

    closeLibrary(handle);
    deleteLibrary(candidate);
}

#ifdef OS_WIN
static DWORD WINAPI workerStageThread(void *argument)
#else
static void *workerStageThread(void *argument)
#endif
{
    worker_stage_driver_t *driver = argument;
    for (unsigned int command = 1; command <= 2; ++command)
    {
        condmutexLock(&driver->condition_mutex);
        while (driver->command < command)
        {
            condvarWait(&driver->condition, &driver->condition_mutex);
        }
        condmutexUnlock(&driver->condition_mutex);

        if (command == 1)
        {
            driver->tunnel->onWorkerQuiesce(driver->tunnel, 7, driver->context);
        }
        else
        {
            driver->tunnel->onWorkerStop(driver->tunnel, 7, driver->context);
        }

        condmutexLock(&driver->condition_mutex);
        driver->completed = command;
        condvarBroadCast(&driver->condition);
        condmutexUnlock(&driver->condition_mutex);
    }
#ifdef OS_WIN
    return 0;
#else
    return NULL;
#endif
}

static void driveWorkerStage(worker_stage_driver_t *driver, unsigned int command)
{
    condmutexLock(&driver->condition_mutex);
    driver->command = command;
    condvarBroadCast(&driver->condition);
    while (driver->completed < command)
    {
        condvarWait(&driver->condition, &driver->condition_mutex);
    }
    condmutexUnlock(&driver->condition_mutex);
}

static void verifyLifecycleV2(const char *path, const char *directory)
{
    const char *type = "LifecycleV2Fixture";
    char        candidate[MAX_PATH];
    stageCandidate(path, directory, type, candidate, sizeof(candidate));
    void *handle = openLibrary(candidate);
    require(handle != NULL, "failed to open lifecycle-v2 fixture");

    LifecycleReset        reset         = NULL;
    LifecycleSetAllocator set_allocator = NULL;
    LifecycleGetSnapshot  get_snapshot  = NULL;
    loadSymbol(handle, "lifecycleNodeFixtureReset", &reset, sizeof(reset));
    loadSymbol(handle, "lifecycleNodeFixtureSetAllocator", &set_allocator, sizeof(set_allocator));
    loadSymbol(handle, "lifecycleNodeFixtureGetSnapshot", &get_snapshot, sizeof(get_snapshot));
    set_allocator(memoryAllocate);
    reset();

    node_t node = nodelibraryLoadByTypeName(type);
    require(node.createHandle != NULL, "lifecycle ABI v2 fixture was rejected");
    tunnel_t *tunnel = nodemanagerCreateTunnelInstance(&node);
    require(tunnel != NULL, "lifecycle ABI v2 tunnel construction failed");

    const ww_lifecycle_context_t context = {
        .scope        = kWwLifecycleProcessShutdown,
        .close_policy = kWwLifecycleCloseGraceful,
    };
    worker_stage_driver_t driver = {
        .tunnel  = tunnel,
        .context = &context,
    };
    condmutexInit(&driver.condition_mutex);
    condvarInit(&driver.condition);

#ifdef OS_WIN
    HANDLE thread = CreateThread(NULL, 0, workerStageThread, &driver, 0, NULL);
    require(thread != NULL, "failed to create lifecycle worker thread");
#else
    pthread_t thread;
    require(pthread_create(&thread, NULL, workerStageThread, &driver) == 0, "failed to create lifecycle worker thread");
#endif

    tunnel->onQuiesceRequest(tunnel, &context);
    driveWorkerStage(&driver, 1);
    tunnel->onQuiesceWait(tunnel, &context);
    driveWorkerStage(&driver, 2);
#ifdef OS_WIN
    require(WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0, "failed to join lifecycle worker thread");
    CloseHandle(thread);
#else
    require(pthread_join(thread, NULL) == 0, "failed to join lifecycle worker thread");
#endif
    tunnel->onStop(tunnel, &context);
    tunnel->onDestroy(tunnel, &context);

    lifecycle_node_fixture_snapshot_t snapshot;
    get_snapshot(&snapshot);
    require(snapshot.count == kLifecycleNodeFixtureStageCount, "lifecycle fixture did not receive every stage");
    for (unsigned int i = 0; i < kLifecycleNodeFixtureStageCount; ++i)
    {
        require(snapshot.stages[i] == i + 1, "lifecycle stages ran out of order");
        require(snapshot.scopes[i] == kWwLifecycleProcessShutdown, "lifecycle scope was not propagated");
        require(snapshot.close_policies[i] == kWwLifecycleCloseGraceful, "lifecycle close policy was not propagated");
    }
    require(snapshot.worker_wids[0] == 7 && snapshot.worker_wids[1] == 7,
            "worker lifecycle stages received the wrong worker id");
    require(snapshot.thread_tokens[0] == snapshot.thread_tokens[2] &&
                snapshot.thread_tokens[0] == snapshot.thread_tokens[4] &&
                snapshot.thread_tokens[0] == snapshot.thread_tokens[5],
            "main lifecycle stages did not share one thread");
    require(snapshot.thread_tokens[1] == snapshot.thread_tokens[3] &&
                snapshot.thread_tokens[1] != snapshot.thread_tokens[0],
            "worker lifecycle stages did not run on one distinct owner thread");

    contvarDestroy(&driver.condition);
    condmutexDestroy(&driver.condition_mutex);
    nodelibraryCleanup();
    closeLibrary(handle);
    deleteLibrary(candidate);
}

int main(void)
{
    char directory[MAX_PATH];
    libraryDirectory(LIFECYCLE_V2_NODE_LIBRARY_PATH, directory, sizeof(directory));
    nodelibrarySetSearchPath(directory);

    verifyRejectedLibrary(MISSING_NODE_LIBRARY_PATH, directory, "MissingAbiFixture");
    verifyRejectedLibrary(MISMATCHED_NODE_LIBRARY_PATH, directory, "MismatchedAbiFixture");
    verifyLifecycleV2(LIFECYCLE_V2_NODE_LIBRARY_PATH, directory);

    puts("lifecycle node ABI v2 tests passed");
    return 0;
}
