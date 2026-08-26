#include "startup_options.h"

#include "wlibc.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

#define WATERWALL_CORE_JSON_INPUT_ENV        "WW_CORE_JSON_INPUT"
#define WATERWALL_DEFAULT_CORE_JSON_INPUT    "core.json"
#define WATERWALL_CORE_JSON_INITIAL_CAPACITY 4096U

static bool isVersionArgument(const char *arg)
{
    return stringCompare(arg, "-v") == 0 || stringCompare(arg, "-version") == 0 ||
           stringCompare(arg, "--version") == 0 || stringCompare(arg, "--v") == 0 || stringCompare(arg, "version") == 0;
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
        const size_t prefix_length = stringLength(prefixes[i]);
        if (strncmp(arg, prefixes[i], prefix_length) == 0)
        {
            return arg + prefix_length;
        }
    }
    return NULL;
}

static void printUsage(const char *program_name)
{
    printError("Usage:\n"
               "  %s [-v|--v|-version|--version|version]\n"
               "  %s [-c:PATH|--c:PATH|-config:PATH|--config:PATH|config:PATH]\n",
               program_name,
               program_name);
}

waterwall_startup_arguments_result_e waterwallStartupOptionsParse(int argc, char *const argv[],
                                                                  waterwall_startup_options_t *options)
{
    if (argc < 1 || argv == NULL || argv[0] == NULL || options == NULL)
    {
        printError("Invalid process arguments supplied to Waterwall\n");
        return kWaterwallStartupArgumentsExitFailure;
    }

    const char *program_name     = argv[0];
    const char *cli_core_input   = NULL;
    bool        version_argument = false;

    for (int i = 1; i < argc; ++i)
    {
        const char *arg = argv[i];
        if (arg == NULL)
        {
            printError("Invalid null command-line argument at position %d\n", i);
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }

        if (isVersionArgument(arg))
        {
            version_argument = true;
            continue;
        }

        const char *config_value = configArgumentValue(arg);
        if (config_value == NULL)
        {
            printError("Invalid command-line argument \"%s\"\n", arg);
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        if (config_value[0] == '\0')
        {
            printError("The core JSON input option \"%s\" requires a non-empty value after ':'\n", arg);
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        if (cli_core_input != NULL)
        {
            printError("The core JSON input option may only be specified once\n");
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }
        cli_core_input = config_value;
    }

    if (version_argument)
    {
        if (argc != 2)
        {
            printError("A version argument cannot be combined with other command-line arguments\n");
            printUsage(program_name);
            return kWaterwallStartupArgumentsExitFailure;
        }

        printDebug("Waterwall version %s\n", TOSTRING(WATERWALL_VERSION));
        return kWaterwallStartupArgumentsExitSuccess;
    }

    const char *core_input = cli_core_input;
    if (core_input == NULL)
    {
        core_input = getenv(WATERWALL_CORE_JSON_INPUT_ENV);
        if (core_input != NULL && core_input[0] == '\0')
        {
            printError("%s is set but does not contain a core JSON input path or 'stdin'\n",
                       WATERWALL_CORE_JSON_INPUT_ENV);
            return kWaterwallStartupArgumentsExitFailure;
        }
    }
    if (core_input == NULL)
    {
        core_input = WATERWALL_DEFAULT_CORE_JSON_INPUT;
    }

    options->core_json_input      = core_input;
    options->core_json_from_stdin = stringCompare(core_input, "stdin") == 0;
    return kWaterwallStartupArgumentsRun;
}

static void reportOpenFailure(const char *path, int error_number)
{
    const char *reason = error_number != 0 ? strerror(error_number) : "input/output error";
    printError("Could not open core settings file \"%s\": %s\n", path, reason);
}

static void reportReadFailure(const waterwall_startup_options_t *options, const char *reason)
{
    if (options->core_json_from_stdin)
    {
        printError("Could not read core settings JSON from standard input: %s\n", reason);
    }
    else
    {
        printError("Could not read core settings file \"%s\": %s\n", options->core_json_input, reason);
    }
}

char *waterwallStartupOptionsReadCoreJson(const waterwall_startup_options_t *options)
{
    if (options == NULL || options->core_json_input == NULL)
    {
        printError("Could not read core settings: no input source was selected\n");
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

    size_t capacity = WATERWALL_CORE_JSON_INITIAL_CAPACITY;
    size_t length   = 0;
    char  *content  = memoryAllocate(capacity);
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
        if (length == capacity - 1)
        {
            if (capacity > SIZE_MAX / 2)
            {
                reportReadFailure(options, "input is too large");
                memoryFree(content);
                if (! options->core_json_from_stdin)
                {
                    (void) fclose(input);
                }
                return NULL;
            }

            const size_t new_capacity = capacity * 2;
            char        *grown        = memoryReAllocate(content, new_capacity);
            if (grown == NULL)
            {
                reportReadFailure(options, "out of memory");
                memoryFree(content);
                if (! options->core_json_from_stdin)
                {
                    (void) fclose(input);
                }
                return NULL;
            }
            content  = grown;
            capacity = new_capacity;
        }

        errno                   = 0;
        const size_t bytes_read = fread(content + length, 1, capacity - length - 1, input);
        const int    read_errno = errno;
        length += bytes_read;
        if (bytes_read != 0)
        {
            continue;
        }
        if (ferror(input))
        {
            const char *reason = read_errno != 0 ? strerror(read_errno) : "input/output error";
            reportReadFailure(options, reason);
            memoryFree(content);
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
            reportReadFailure(options, close_error != 0 ? strerror(close_error) : "input/output error");
            memoryFree(content);
            return NULL;
        }
    }

    if (options->core_json_from_stdin && length == 0)
    {
        reportReadFailure(options, "standard input ended before any JSON was received");
        memoryFree(content);
        return NULL;
    }

    content[length] = '\0';
    return content;
}

void waterwallStartupOptionsReportCoreJsonParseFailure(const waterwall_startup_options_t *options)
{
    if (options->core_json_from_stdin)
    {
        printError("Could not parse core settings JSON from standard input\n");
    }
    else
    {
        printError("Could not parse core settings JSON from file \"%s\"\n", options->core_json_input);
    }
}
