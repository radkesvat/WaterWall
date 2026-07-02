/*
 * Implements node library registration and on-demand dynamic loading.
 */

#include "node_library.h"

#include "worker.h"

#include "loggers/internal_logger.h"

#ifdef OS_WIN
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#define i_type vec_static_libs // NOLINT
#define i_key  node_t          // NOLINT
#include "stc/vec.h"

#define i_type vec_dynamic_libs // NOLINT
#define i_key  void *           // NOLINT
#include "stc/vec.h"

static struct
{
    char             *search_path;
    vec_static_libs   slibs;
    vec_dynamic_libs  dlibs;
} *nodelib_state;

enum
{
    kDirCandidatesCount  = 12,
    kFileCandidatesCount = 16,
};

typedef node_t (*node_get_fn)(void);

/**
 * @brief Lazily initialize global node-library state.
 */
static void nodelibraryEnsureStateInitialized(void)
{
    if (nodelib_state != NULL)
    {
        return;
    }
    nodelib_state = memoryAllocateZero(sizeof(*nodelib_state));
    nodelib_state->slibs = vec_static_libs_init();
    nodelib_state->dlibs = vec_dynamic_libs_init();
}

void nodelibrarySetSearchPath(const char *path)
{
    nodelibraryEnsureStateInitialized();

    memoryFree(nodelib_state->search_path);
    nodelib_state->search_path = NULL;

    if (path != NULL && *path != '\0')
    {
        nodelib_state->search_path = stringDuplicate(path);
    }
}

/**
 * @brief Add a non-empty path only if not already present.
 *
 * @param paths Destination path list.
 * @param count Current path count (updated on insert).
 * @param max_count Maximum allowed entries.
 * @param path Candidate path.
 */
static void pushUniquePath(const char **paths, size_t *count, size_t max_count, const char *path)
{
    if (path == NULL || *path == '\0' || *count >= max_count)
    {
        return;
    }

    for (size_t i = 0; i < *count; i++)
    {
        if (strcmp(paths[i], path) == 0)
        {
            return;
        }
    }

    paths[(*count)++] = path;
}

/**
 * @brief Build a path using optional directory and file name.
 *
 * @param out Output buffer.
 * @param out_size Output buffer size.
 * @param dir Optional directory.
 * @param file File name.
 * @return true Path was built successfully.
 * @return false Input invalid or output truncated.
 */
static bool buildPath(char *out, size_t out_size, const char *dir, const char *file)
{
    if (out == NULL || out_size == 0 || file == NULL || *file == '\0')
    {
        return false;
    }

    if (dir == NULL || *dir == '\0')
    {
        int n = snprintf(out, out_size, "%s", file);
        return (n > 0) && ((size_t) n < out_size);
    }

    char last = dir[strlen(dir) - 1];
    if (last == '/' || last == '\\')
    {
        int n = snprintf(out, out_size, "%s%s", dir, file);
        return (n > 0) && ((size_t) n < out_size);
    }

    int n = snprintf(out, out_size, "%s/%s", dir, file);
    return (n > 0) && ((size_t) n < out_size);
}

/**
 * @brief Open a dynamic library.
 *
 * @param lib_path Library file path.
 * @return void* Platform-native library handle, or NULL.
 */
static void *dynOpenLibrary(const char *lib_path)
{
#ifdef OS_WIN
    return (void *) LoadLibraryA(lib_path);
#else
    return dlopen(lib_path, RTLD_NOW | RTLD_LOCAL);
#endif
}

/**
 * @brief Close a previously opened dynamic library handle.
 *
 * @param lib_handle Library handle.
 */
static void dynCloseLibrary(void *lib_handle)
{
    if (lib_handle == NULL)
    {
        return;
    }
#ifdef OS_WIN
    FreeLibrary((HMODULE) lib_handle);
#else
    dlclose(lib_handle);
#endif
}

/**
 * @brief Resolve a symbol from a dynamic library handle into caller storage.
 *
 * @param lib_handle Library handle.
 * @param symbol_name Symbol to resolve.
 * @param out_symbol Destination for the resolved symbol bytes.
 * @param out_symbol_size Size of @p out_symbol in bytes.
 * @return true Symbol resolved and copied into caller storage.
 * @return false Input invalid or symbol not found.
 */
static bool dynGetSymbol(void *lib_handle, const char *symbol_name, void *out_symbol, size_t out_symbol_size)
{
    if (lib_handle == NULL || symbol_name == NULL || *symbol_name == '\0' || out_symbol == NULL || out_symbol_size == 0)
    {
        return false;
    }
#ifdef OS_WIN
    FARPROC symbol_addr = GetProcAddress((HMODULE) lib_handle, symbol_name);
#else
    void *symbol_addr = dlsym(lib_handle, symbol_name);
#endif

    if (symbol_addr == NULL)
    {
        return false;
    }

    memoryCopy(out_symbol, &symbol_addr, out_symbol_size);
    return true;
}

/**
 * @brief Resolve supported node getter symbol variants from a library.
 *
 * @param lib_handle Library handle.
 * @param htype Target node type hash.
 * @return node_get_fn Function pointer to node getter, or NULL.
 */
static node_get_fn dynResolveNodeGetter(void *lib_handle, hash_t htype)
{
    char hash_sym_1[64] = {0};
    char hash_sym_2[64] = {0};
    char hash_sym_3[64] = {0};

    unsigned long long hv = (unsigned long long) htype;

    snprintf(hash_sym_1, sizeof(hash_sym_1), "nodeGet_%016llx", hv);
    snprintf(hash_sym_2, sizeof(hash_sym_2), "wwNodeGet_%016llx", hv);
    snprintf(hash_sym_3, sizeof(hash_sym_3), "waterwallNodeGet_%016llx", hv);

    const char *symbols[] = {
        "nodeGet",
        "wwNodeGet",
        "waterwallNodeGet",
        hash_sym_1,
        hash_sym_2,
        hash_sym_3,
    };

    for (size_t i = 0; i < sizeof(symbols) / sizeof(symbols[0]); i++)
    {
        node_get_fn getter = NULL;
        if (dynGetSymbol(lib_handle, symbols[i], &getter, sizeof(getter)) && getter != NULL)
        {
            return getter;
        }
    }
    return NULL;
}

/**
 * @brief Try loading a node library by hash from known file/path candidates.
 *
 * @param htype Node type hash.
 * @return node_t Loaded node definition, or zeroed node on failure.
 */
static node_t dynLoadNodeLib(hash_t htype)
{
    char exe_dir[MAX_PATH]      = {0};
    char run_dir[MAX_PATH]      = {0};
    char exe_libs_dir[MAX_PATH] = {0};
    char run_libs_dir[MAX_PATH] = {0};

    char file_candidates[kFileCandidatesCount][MAX_PATH] = {0};
    size_t file_candidates_len                            = 0;

    const char *env_libs_path = getenv("WW_LIBS_PATH");
    const char *dirs[kDirCandidatesCount];
    size_t      dirs_len = 0;

#ifdef OS_WIN
    const char *lib_ext = ".dll";
#elif defined(OS_MAC)
    const char *lib_ext = ".dylib";
#else
    const char *lib_ext = ".so";
#endif

    unsigned long long hv = (unsigned long long) htype;

#define PUSH_LIB_CANDIDATE(fmt, val, ext)                                                                     \
    do                                                                                                        \
    {                                                                                                         \
        if (file_candidates_len < kFileCandidatesCount)                                                       \
        {                                                                                                     \
            snprintf(file_candidates[file_candidates_len], sizeof(file_candidates[file_candidates_len]), fmt, \
                     val, ext);                                                                               \
            file_candidates_len++;                                                                            \
        }                                                                                                     \
    } while (0)

    PUSH_LIB_CANDIDATE("ww-node-%016llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("node-%016llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("%016llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("libww-node-%016llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("libnode-%016llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("lib%016llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("ww-node-%llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("node-%llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("%llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("libww-node-%llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("libnode-%llx%s", hv, lib_ext);
    PUSH_LIB_CANDIDATE("lib%llx%s", hv, lib_ext);

#undef PUSH_LIB_CANDIDATE

    if (nodelib_state != NULL)
    {
        pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, nodelib_state->search_path);
    }
    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, env_libs_path);

    if (getExecuteableDir(exe_dir, sizeof(exe_dir)) != NULL)
    {
        buildPath(exe_libs_dir, sizeof(exe_libs_dir), exe_dir, "libs");
    }

    if (getRunDir(run_dir, sizeof(run_dir)) != NULL)
    {
        buildPath(run_libs_dir, sizeof(run_libs_dir), run_dir, "libs");
    }

    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, "libs");
    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, exe_libs_dir);
    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, run_libs_dir);
    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, exe_dir);
    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, run_dir);
    pushUniquePath(dirs, &dirs_len, kDirCandidatesCount, ".");

    for (size_t di = 0; di < dirs_len; di++)
    {
        for (size_t fi = 0; fi < file_candidates_len; fi++)
        {
            char full_path[MAX_PATH] = {0};
            if (! buildPath(full_path, sizeof(full_path), dirs[di], file_candidates[fi]))
            {
                continue;
            }

            void *handle = dynOpenLibrary(full_path);
            if (handle == NULL)
            {
                continue;
            }

            node_get_fn getter = dynResolveNodeGetter(handle, htype);
            if (getter == NULL)
            {
                dynCloseLibrary(handle);
                continue;
            }

            node_t lib = getter();

            if (lib.hash_type == 0 && lib.type != NULL && *lib.type != '\0')
            {
                lib.hash_type = calcHashBytes(lib.type, strlen(lib.type));
            }

            if (lib.hash_type != htype || lib.createHandle == NULL)
            {
                dynCloseLibrary(handle);
                continue;
            }

            nodelibraryEnsureStateInitialized();
            vec_dynamic_libs_push(&(nodelib_state->dlibs), handle);
            vec_static_libs_push(&(nodelib_state->slibs), lib);

            LOGI("NodeLibrary: dynamically loaded node lib \"%s\" (hash: %lx)", full_path, (unsigned long) htype);
            return lib;
        }
    }

    LOGD("NodeLibrary: dynamic node lib not found for hash: %lx", (unsigned long) htype);
    return (node_t) {0};
}

node_t nodelibraryLoadByTypeHash(hash_t htype)
{

    if (nodelib_state != NULL)
    {
        c_foreach(k, vec_static_libs, nodelib_state->slibs)
        {
            if ((k.ref)->hash_type == htype)
            {
                return *(k.ref);
            }
        }
    }
    return dynLoadNodeLib(htype);
}

node_t nodelibraryLoadByTypeName(const char *name)
{
    if (name == NULL || *name == '\0')
    {
        return (node_t) {0};
    }
    hash_t htype = calcHashBytes(name, strlen(name));
    return nodelibraryLoadByTypeHash(htype);
}

void nodelibraryRegister(node_t lib)
{
    nodelibraryEnsureStateInitialized();

    vec_static_libs_push(&(nodelib_state->slibs), lib);
}

bool nodeHasFlagChainHead(node_t *node)
{
    return (node->flags & kNodeFlagChainHead) == kNodeFlagChainHead;
}

void nodelibraryCleanup(void)
{
    if (nodelib_state != NULL)
    {
        c_foreach(k, vec_static_libs, nodelib_state->slibs)
        {
            memoryFree((k.ref)->type);
        }
        vec_static_libs_drop(&(nodelib_state->slibs));

        c_foreach(k, vec_dynamic_libs, nodelib_state->dlibs)
        {
            dynCloseLibrary(*(k.ref));
        }
        vec_dynamic_libs_drop(&(nodelib_state->dlibs));

        memoryFree(nodelib_state->search_path);
        nodelib_state->search_path = NULL;
    }
    memoryFree(nodelib_state);
    nodelib_state = NULL;
}
