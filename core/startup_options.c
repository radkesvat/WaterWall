#include "startup_options.h"

#include "config_lexical.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#ifdef _WIN32
#include "startup_windows.h"
#include <io.h>
#else
#include <unistd.h>
#endif

#ifndef WATERWALL_VERSION
#define WATERWALL_VERSION 1.46.9
#endif

#define WW_STR_INNER(x) #x
#define WW_STR(x)       WW_STR_INNER(x)

#define WATERWALL_CORE_JSON_INPUT_ENV        "WW_CORE_JSON_INPUT"
#define WATERWALL_DEFAULT_CORE_JSON_INPUT    "core.json"
#define WATERWALL_CORE_JSON_INITIAL_CAPACITY 4096U

static bool isVersionArgument(const char *arg)
{
    return strcmp(arg, "-v") == 0 || strcmp(arg, "-version") == 0 || strcmp(arg, "--version") == 0 ||
           strcmp(arg, "--v") == 0 || strcmp(arg, "version") == 0;
}

static const char *configArgumentValue(const char *arg)
{
    static const char *prefixes[] = {
        "-c:",
        "--c:",
        "-config:",
        "--config:",
        "config:",
    };

    for (size_t i = 0; i < sizeof(prefixes) / sizeof(prefixes[0]); ++i)
    {
        const size_t prefix_length = strlen(prefixes[i]);
        if (strncmp(arg, prefixes[i], prefix_length) == 0)
        {
            return arg + prefix_length;
        }
    }
    return NULL;
}

#ifdef _WIN32
static bool parseLifecycleHandle(const char *value, uintptr_t *event)
{
    uintptr_t parsed = 0;
    if (*value == '\0')
    {
        return false;
    }
    for (const char *cursor = value; *cursor != '\0'; ++cursor)
    {
        if (*cursor < '0' || *cursor > '9')
        {
            return false;
        }
        const uintptr_t digit = (uintptr_t) (*cursor - '0');
        if (parsed > (UINTPTR_MAX - digit) / 10U)
        {
            return false;
        }
        parsed = parsed * 10U + digit;
    }
    if (parsed == 0 || parsed == UINTPTR_MAX)
    {
        return false;
    }
    *event = parsed;
    return true;
}
#endif

static void printUsage(const char *program_name)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s [-v|--v|-version|--version|version]\n"
            "  %s [--restricted-config] [-c:PATH|--c:PATH|-config:PATH|--config:PATH|config:PATH]\n",
            program_name,
            program_name);
#ifdef _WIN32
    fprintf(stderr,
            "  Windows lifecycle capabilities: [--stop-event:HANDLE] [--ready-event:HANDLE] "
            "[--controller-process:HANDLE]\n"
            "  [--console:hidden|--console:visible] [--session-file:NEW_PATH]\n"
            "  Recovery: --recover:PATH (used alone)\n");
#endif
}

waterwall_startup_arguments_result_e waterwallStartupOptionsParse(int argc, char *const argv[],
                                                                  waterwall_startup_options_t *options)
{
    if (argc < 1 || argv == NULL || argv[0] == NULL || options == NULL)
    {
        fprintf(stderr, "Invalid process arguments supplied to Waterwall\n");
        return kWaterwallStartupArgumentsExitFailure;
    }

    const char *program_name      = argv[0];
    const char *cli_core_input    = NULL;
    bool        version_argument  = false;
    bool        restricted_config = false;
    uintptr_t   stop_event         = 0;
    uintptr_t   ready_event        = 0;
    uintptr_t   controller_process = 0;

    const char *session_file = NULL, *recover_file = NULL;
    unsigned    console_mode = 0;

    for (int i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (arg == NULL)
        {
            fprintf(stderr, "Invalid null command-line argument at position %d\n", i);
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }

        if (strcmp(arg, "--restricted-config") == 0)
        {
            if (restricted_config)
            {
                fprintf(stderr, "The restricted configuration option may only be specified once\n");
                return kWaterwallStartupArgumentsExitFailure;
            }
            restricted_config = true;
            continue;
        }

        if (strncmp(arg, "--session-file:", 15) == 0 || strncmp(arg, "--recover:", 10) == 0 ||
            strncmp(arg, "--console:", 10) == 0)
        {
#ifdef _WIN32
            if (strncmp(arg, "--console:", 10) == 0)
            {
                if (console_mode != 0 || (strcmp(arg + 10, "hidden") != 0 && strcmp(arg + 10, "visible") != 0))
                    return kWaterwallStartupArgumentsExitFailure;
                console_mode = strcmp(arg + 10, "hidden") == 0 ? 1 : 2;
            }
            else
            {
                bool         recovery = strncmp(arg, "--recover:", 10) == 0;
                const char **value    = recovery ? &recover_file : &session_file;
                if (*value != NULL || arg[recovery ? 10 : 15] == '\0')
                    return kWaterwallStartupArgumentsExitFailure;
                *value = arg + (recovery ? 10 : 15);
            }
            continue;
#else
            fprintf(stderr, "Session options are available only on Windows\n");
            return kWaterwallStartupArgumentsExitFailure;
#endif
        }

        const char *capability_names[] = {"--stop-event:", "--ready-event:", "--controller-process:"};
        uintptr_t  *capabilities[]     = {&stop_event, &ready_event, &controller_process};
        bool        capability         = false;
        for (size_t c = 0; c < 3; ++c)
        {
            size_t prefix = strlen(capability_names[c]);
            if (strncmp(arg, capability_names[c], prefix) != 0)
                continue;
#ifdef _WIN32
            if (*capabilities[c] != 0 || ! parseLifecycleHandle(arg + prefix, capabilities[c]))
            {
                fprintf(stderr, "Invalid or duplicate lifecycle capability\n");
                return kWaterwallStartupArgumentsExitFailure;
            }
            capability = true;
#else
            (void) capabilities;
            fprintf(stderr, "Lifecycle capabilities are available only on Windows\n");
            return kWaterwallStartupArgumentsExitFailure;
#endif
        }
        if (capability)
            continue;

        if (isVersionArgument(arg))
        {
            version_argument = true;
            continue;
        }

        const char *config_value = configArgumentValue(arg);
        if (config_value == NULL)
        {
            fprintf(stderr, "Invalid command-line argument \"%s\"\n", arg);
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        if (config_value[0] == '\0')
        {
            fprintf(stderr, "The core JSON input option \"%s\" requires a non-empty value after ':'\n", arg);
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        if (cli_core_input != NULL)
        {
            fprintf(stderr, "The core JSON input option may only be specified once\n");
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        cli_core_input = config_value;
    }

    if ((stop_event != 0 && stop_event == ready_event) ||
        (controller_process != 0 && (controller_process == stop_event || controller_process == ready_event)))
    {
        fprintf(stderr, "Lifecycle capabilities must use distinct handles\n");
        return kWaterwallStartupArgumentsExitFailure;
    }

    if (version_argument)
    {
        if (argc != 2)
        {
            fprintf(stderr, "A version argument cannot be combined with other command-line arguments\n");
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        printf("Waterwall version %s\n", WW_STR(WATERWALL_VERSION));
        return kWaterwallStartupArgumentsExitSuccess;
    }

    if (recover_file != NULL && argc != 2)
    {
        fprintf(stderr, "Recovery cannot be combined with launch arguments\n");
        return kWaterwallStartupArgumentsExitFailure;
    }
    if (recover_file != NULL)
    {
        *options = (waterwall_startup_options_t) {.recover_file = recover_file};
        return kWaterwallStartupArgumentsRun;
    }

    options->session_file = session_file;
    options->recover_file = recover_file;
    options->console_mode = console_mode;

    const char *core_input = cli_core_input;
    if (core_input == NULL)
    {
        core_input = getenv(WATERWALL_CORE_JSON_INPUT_ENV);
        if (core_input != NULL && core_input[0] == '\0')
        {
            fprintf(stderr,
                    "%s is set but does not contain a core JSON input path or 'stdin'\n",
                    WATERWALL_CORE_JSON_INPUT_ENV);
            return kWaterwallStartupArgumentsExitFailure;
        }
    }
    if (core_input == NULL)
    {
        core_input = WATERWALL_DEFAULT_CORE_JSON_INPUT;
    }

    options->restricted_config    = restricted_config;
    options->stop_event           = stop_event;
    options->ready_event          = ready_event;
    options->controller_process   = controller_process;
    options->core_json_input      = core_input;
    options->core_json_from_stdin = (strcmp(core_input, "stdin") == 0);
    return kWaterwallStartupArgumentsRun;
}

static void reportOpenFailure(const char *path, int error_number)
{
    const char *reason = error_number != 0 ? strerror(error_number) : "input/output error";
    fprintf(stderr, "Waterwall version %s\n", WW_STR(WATERWALL_VERSION));
    fprintf(stderr, "Could not open core settings file \"%s\": %s\n", path, reason);
}

static void reportReadFailure(const waterwall_startup_options_t *options, const char *reason)
{
    fprintf(stderr, "Waterwall version %s\n", WW_STR(WATERWALL_VERSION));
    if (options->core_json_from_stdin)
    {
        fprintf(stderr, "Could not read core settings JSON from standard input: %s\n", reason);
    }
    else
    {
        fprintf(stderr, "Could not read core settings file \"%s\": %s\n", options->core_json_input, reason);
    }
}

char *waterwallStartupOptionsReadCoreJson(const waterwall_startup_options_t *options, size_t *out_length)
{
    if (options == NULL || options->core_json_input == NULL)
    {
        fprintf(stderr, "Could not read core settings: no input source was selected\n");
        return NULL;
    }

    FILE *input = stdin;
    if (! options->core_json_from_stdin)
    {
        errno = 0;
        input = fopen(options->core_json_input, "rb");
        if (input == NULL)
        {
            const int open_error = errno;
            reportOpenFailure(options->core_json_input, open_error);
            return NULL;
        }
    }
#ifdef _WIN32
    else
    {
        if (options->restricted_config && _setmode(_fileno(input), _O_BINARY) == -1)
        {
            fprintf(stderr, "Restricted config: could not select binary stdin\n");
            return NULL;
        }
    }
#endif

    const size_t limit    = options->restricted_config ? WW_HOST_CORE_JSON_LIMIT : SIZE_MAX - 1;
    size_t       capacity = WATERWALL_CORE_JSON_INITIAL_CAPACITY;
    size_t       length   = 0;
    char        *content  = malloc(capacity);
    if (content == NULL)
    {
        reportReadFailure(options, "out of memory");
        if (! options->core_json_from_stdin)
        {
            (void) fclose(input);
        }
        return NULL;
    }

    while (true)
    {
        if (length == limit)
        {
            if (fgetc(input) == EOF && ! ferror(input))
            {
                break;
            }
            if (options->restricted_config)
            {
                fprintf(stderr, "Restricted config: input limit or read failure at byte %zu\n", length);
            }
            else
            {
                reportReadFailure(options, "input is too large");
            }
            free(content);
            if (! options->core_json_from_stdin)
            {
                (void) fclose(input);
            }
            return NULL;
        }

        if (length == capacity - 1)
        {
            size_t new_capacity = capacity > SIZE_MAX / 2 ? SIZE_MAX : capacity * 2;
            if (new_capacity > limit + 1)
            {
                new_capacity = limit + 1;
            }
            char *grown = realloc(content, new_capacity);
            if (grown == NULL)
            {
                reportReadFailure(options, "out of memory");
                free(content);
                if (! options->core_json_from_stdin)
                {
                    (void) fclose(input);
                }
                return NULL;
            }
            content  = grown;
            capacity = new_capacity;
        }

        size_t max_read = capacity - length - 1;
        if (max_read > limit - length)
        {
            max_read = limit - length;
        }

        errno                   = 0;
        const size_t bytes_read = fread(content + length, 1, max_read, input);
        const int    read_errno = errno;
        length += bytes_read;
        if (bytes_read != 0)
        {
            continue;
        }
        if (ferror(input))
        {
            const char *reason = read_errno != 0 ? strerror(read_errno) : "input/output error";
            if (options->restricted_config)
            {
                fprintf(stderr, "Restricted config: read failure at byte %zu\n", length);
            }
            else
            {
                reportReadFailure(options, reason);
            }
            free(content);
            if (! options->core_json_from_stdin)
            {
                (void) fclose(input);
            }
            return NULL;
        }
        break;
    }

    if (! options->core_json_from_stdin)
    {
        errno = 0;
        if (fclose(input) != 0)
        {
            const int close_error = errno;
            if (options->restricted_config)
            {
                fprintf(stderr, "Restricted config: input close failure\n");
            }
            else
            {
                reportReadFailure(options, close_error != 0 ? strerror(close_error) : "input/output error");
            }
            free(content);
            return NULL;
        }
    }

    if (options->core_json_from_stdin && length == 0)
    {
        reportReadFailure(options, "standard input ended before any JSON was received");
        free(content);
        return NULL;
    }

    content[length] = '\0';

    if (options->restricted_config)
    {
        if (! configLexicalCheckEncoding(content, length))
        {
            free(content);
            return NULL;
        }
    }

    if (out_length != NULL)
    {
        *out_length = length;
    }
    return content;
}

void waterwallStartupOptionsFreeCoreJson(char *content)
{
    free(content);
}

void waterwallStartupOptionsReportCoreJsonParseFailure(const waterwall_startup_options_t *options)
{
    if (options->core_json_from_stdin)
    {
        fprintf(stderr, "Could not parse core settings JSON from standard input\n");
    }
    else
    {
        fprintf(stderr, "Could not parse core settings JSON from file \"%s\"\n", options->core_json_input);
    }
}

int waterwallStartupHandoffExtract(int *argc, char **argv, waterwall_handoff_t *handoff)
{
    if (argc == NULL || *argc <= 1 || argv == NULL || handoff == NULL)
    {
        return 0;
    }

    handoff->fd         = -1;
    const char *fd_str  = NULL;
    const char *len_str = NULL;
    const char *src_str = NULL;
    const char *exe_str = NULL;
    int         matched = 0;
    uintptr_t   completion_event = 0, effects_mapping = 0;

    for (int i = 1; i < *argc; ++i)
    {
        const char *arg = argv[i];
        if (arg == NULL)
            continue;

#ifdef _WIN32
#define WW_HANDOFF_HANDLE_ARG "--ww-internal-map="
#else
#define WW_HANDOFF_HANDLE_ARG "--ww-internal-fd="
#endif
        if (strncmp(arg, WW_HANDOFF_HANDLE_ARG, sizeof(WW_HANDOFF_HANDLE_ARG) - 1) == 0)
        {
            if (fd_str != NULL)
                return -1;
            fd_str = arg + sizeof(WW_HANDOFF_HANDLE_ARG) - 1;
            ++matched;
        }
        else if (strncmp(arg, "--ww-internal-len=", sizeof("--ww-internal-len=") - 1) == 0)
        {
            if (len_str != NULL)
                return -1;
            len_str = arg + sizeof("--ww-internal-len=") - 1;
            ++matched;
        }
        else if (strncmp(arg, "--ww-internal-src=", sizeof("--ww-internal-src=") - 1) == 0)
        {
            if (src_str != NULL)
                return -1;
            src_str = arg + sizeof("--ww-internal-src=") - 1;
            ++matched;
        }
        else if (strncmp(arg, "--ww-internal-exe=", sizeof("--ww-internal-exe=") - 1) == 0)
        {
            if (exe_str != NULL)
                return -1;
            exe_str = arg + sizeof("--ww-internal-exe=") - 1;
            ++matched;
        }
#ifdef _WIN32
        else if (strncmp(arg, "--ww-internal-effects=", 22) == 0)
        {
            if (effects_mapping != 0 || ! parseLifecycleHandle(arg + 22, &effects_mapping))
                return -1;
        }
        else if (strncmp(arg, "--ww-internal-complete=", 23) == 0)
        {
            if (completion_event != 0 || ! parseLifecycleHandle(arg + 23, &completion_event))
                return -1;
        }
#endif
        else if (strncmp(arg, "--ww-internal-", 14) == 0)
        {
            return -1;
        }
    }

    if (matched == 0)
    {
        return completion_event == 0 && effects_mapping == 0 ? 0 : -1;
    }
    if (matched != 4 || fd_str == NULL || len_str == NULL || src_str == NULL || exe_str == NULL)
    {
        fprintf(stderr, "Packed runtime: incomplete internal handoff metadata\n");
        return -1;
    }

#if ! defined(__linux__) && ! defined(_WIN32)
    fprintf(stderr, "Internal input handoff is unsupported on this platform\n");
    return -1;
#endif
    char *endptr = NULL;
    errno        = 0;
#ifdef _WIN32
    unsigned long long fd_val = strtoull(fd_str, &endptr, 10);
    if (fd_str[0] < '0' || fd_str[0] > '9' || errno == ERANGE || *endptr != '\0' || fd_val == 0 ||
        fd_val >= UINTPTR_MAX - 16)
#else
    long fd_val = strtol(fd_str, &endptr, 10);
    if (fd_str[0] < '0' || fd_str[0] > '9' || errno == ERANGE || *endptr != '\0' || fd_val <= 2 || fd_val > INT_MAX)
#endif
    {
        fprintf(stderr, "Packed runtime: invalid handoff descriptor\n");
        return -1;
    }

    errno                      = 0;
    unsigned long long len_val = strtoull(len_str, &endptr, 10);
    if (len_str[0] < '0' || len_str[0] > '9' || errno == ERANGE || *endptr != '\0' || len_val == 0 ||
        len_val > SIZE_MAX - 1 || len_val > INT64_MAX)
    {
        fprintf(stderr, "Packed runtime: invalid handoff length\n");
        return -1;
    }

#ifdef _WIN32
    bool absolute = (strlen(exe_str) >= 3 &&
                     ((exe_str[0] >= 'A' && exe_str[0] <= 'Z') || (exe_str[0] >= 'a' && exe_str[0] <= 'z')) &&
                     exe_str[1] == ':' && (exe_str[2] == '\\' || exe_str[2] == '/')) ||
                    (exe_str[0] == '\\' && exe_str[1] == '\\');
#else
    bool absolute = exe_str[0] == '/';
#endif
    if (src_str[0] == '\0' || ! absolute)
    {
        fprintf(stderr, "Packed runtime: invalid handoff paths\n");
        return -1;
    }

    handoff->has_handoff = true;
    handoff->completion_event = completion_event;
    handoff->effects_mapping  = effects_mapping;
#ifdef _WIN32
    handoff->mapping = (uintptr_t) fd_val;
#else
    handoff->fd = (int) fd_val;
#endif
    handoff->length      = (size_t) len_val;
    handoff->source_name = src_str;
    handoff->orig_exe    = exe_str;

    /* Strip internal arguments in-place */
    int new_argc = 1;
    for (int i = 1; i < *argc; ++i)
    {
        if (strncmp(argv[i], "--ww-internal-", 14) != 0)
        {
            argv[new_argc++] = argv[i];
        }
    }
    argv[new_argc] = NULL;
    *argc          = new_argc;
    return 1;
}

#ifdef _WIN32
/* MapViewOfFile can succeed for SEC_RESERVE sections whose pages are not
 * committed. Check the entire read-only view before dereferencing untrusted
 * handoff storage, including a separately mapped transport header. */
static bool windowsSnapshotReadable(const void *view, size_t length)
{
    const unsigned char *cursor = view;
    while (length != 0)
    {
        MEMORY_BASIC_INFORMATION region;
        if (VirtualQuery(cursor, &region, sizeof(region)) == 0 || region.State != MEM_COMMIT ||
            region.Type != MEM_MAPPED || region.Protect != PAGE_READONLY)
            return false;
        size_t available = region.RegionSize - (size_t) (cursor - (const unsigned char *) region.BaseAddress);
        if (available >= length)
            return true;
        cursor += available;
        length -= available;
    }
    return true;
}
#endif

int waterwallStartupHandoffReceive(waterwall_handoff_t *handoff, bool restricted, char **out_content,
                                   size_t *out_length)
{
    if (handoff == NULL || ! handoff->has_handoff || out_content == NULL)
    {
        return -1;
    }

#ifdef __linux__
    if (handoff->fd <= 2)
        return -1;
    const int fd = handoff->fd;
    /* Take ownership immediately: every return below closes the descriptor. */
    handoff->fd = -1;
    if (handoff->length > SIZE_MAX - 1 || (uint64_t) handoff->length > INT64_MAX ||
        (restricted && handoff->length > WW_HOST_CORE_JSON_LIMIT))
    {
        fprintf(stderr, "Input snapshot exceeds the core input limit\n");
        close(fd);
        return -1;
    }
    int flags = fcntl(fd, F_GETFD);
    if (flags < 0 || fcntl(fd, F_SETFD, flags | FD_CLOEXEC) != 0)
    {
        fprintf(stderr, "Packed runtime: handoff descriptor %d inaccessible: %s\n", fd, strerror(errno));
        close(fd);
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) != 0)
    {
        fprintf(stderr, "Packed runtime: handoff fstat failed: %s\n", strerror(errno));
        close(fd);
        handoff->fd = -1;
        return -1;
    }
    if (! S_ISREG(st.st_mode) || st.st_size < 0 || (uint64_t) st.st_size != handoff->length)
    {
        fprintf(stderr,
                "Packed runtime: snapshot must be a regular file of exactly %zu bytes (got %zu)\n",
                handoff->length,
                (size_t) st.st_size);
        close(fd);
        handoff->fd = -1;
        return -1;
    }

    char *buffer = malloc(handoff->length + 1);
    if (buffer == NULL)
    {
        fprintf(stderr, "Packed runtime: out of memory allocating input snapshot\n");
        close(fd);
        handoff->fd = -1;
        return -1;
    }

    size_t total = 0;
    while (total < handoff->length)
    {
        ssize_t n = pread(fd, buffer + total, handoff->length - total, (off_t) total);
        if (n < 0)
        {
            if (errno == EINTR)
                continue;
            fprintf(stderr, "Packed runtime: reading input snapshot failed: %s\n", strerror(errno));
            free(buffer);
            close(fd);
            handoff->fd = -1;
            return -1;
        }
        if (n == 0)
            break;
        total += (size_t) n;
    }

    close(fd);
    handoff->fd = -1;

    if (total != handoff->length)
    {
        fprintf(stderr, "Packed runtime: snapshot read truncated\n");
        free(buffer);
        return -1;
    }

    buffer[total] = '\0';
    *out_content  = buffer;
    if (out_length != NULL)
    {
        *out_length = total;
    }
    return 0;
#elif defined(_WIN32)
    HANDLE mapping   = (HANDLE) handoff->mapping;
    handoff->mapping = 0;
    void *view       = NULL;
    char *buffer     = NULL;
    int   result     = -1;
    if (mapping == NULL || mapping == INVALID_HANDLE_VALUE)
        return -1;
    if (! SetHandleInformation(mapping, HANDLE_FLAG_INHERIT, 0) ||
        handoff->length > SIZE_MAX - sizeof(waterwall_snapshot_header_t) ||
        (restricted && handoff->length > WW_HOST_CORE_JSON_LIMIT))
        goto windows_done;
    /* An internal caller cannot smuggle a writable snapshot into the receiver. */
    view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, sizeof(waterwall_snapshot_header_t));
    if (view != NULL)
        goto windows_done;
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(waterwall_snapshot_header_t));
    if (view == NULL || ! windowsSnapshotReadable(view, sizeof(waterwall_snapshot_header_t)))
        goto windows_done;
    waterwall_snapshot_header_t header;
    memcpy(&header, view, sizeof(header));
    UnmapViewOfFile(view);
    view = NULL;
    if (header.magic != WW_SNAPSHOT_MAGIC || header.length != handoff->length ||
        header.length_inverse != ~header.length)
        goto windows_done;
    view = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, sizeof(header) + handoff->length);
    if (view == NULL || ! windowsSnapshotReadable(view, sizeof(header) + handoff->length))
        goto windows_done;
    buffer = malloc(handoff->length + 1);
    if (buffer == NULL)
        goto windows_done;
    memcpy(buffer, (const char *) view + sizeof(header), handoff->length);
    buffer[handoff->length] = '\0';
    *out_content            = buffer;
    if (out_length != NULL)
        *out_length = handoff->length;
    result = 0;
windows_done:
    if (view != NULL)
        UnmapViewOfFile(view);
    CloseHandle(mapping);
    if (result != 0)
        fprintf(stderr, "Packed runtime: invalid or inaccessible input mapping\n");
    return result;
#else
    (void) restricted;
    (void) out_length;
    return -1;
#endif
}

void waterwallStartupHandoffCleanup(waterwall_handoff_t *handoff)
{
    if (handoff == NULL)
        return;
#ifdef _WIN32
    if (handoff->has_handoff && handoff->mapping != 0)
    {
        CloseHandle((HANDLE) handoff->mapping);
        handoff->mapping = 0;
    }
#endif
    if (handoff->has_handoff && handoff->fd > 2)
    {
#ifdef __linux__
        close(handoff->fd);
#endif
        handoff->fd = -1;
    }
    if (handoff->source_name != NULL)
    {
        handoff->source_name = NULL;
    }
    if (handoff->orig_exe != NULL)
    {
        handoff->orig_exe = NULL;
    }
    handoff->has_handoff = false;
}
