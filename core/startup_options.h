#pragma once

#include <stdbool.h>

typedef enum waterwall_startup_arguments_result_e
{
    kWaterwallStartupArgumentsRun,
    kWaterwallStartupArgumentsExitSuccess,
    kWaterwallStartupArgumentsExitFailure,
} waterwall_startup_arguments_result_e;

typedef struct waterwall_startup_options_s
{
    const char *core_json_input;
    bool        core_json_from_stdin;
} waterwall_startup_options_t;

/**
 * @brief Parse startup arguments and select the core JSON input source.
 *
 * CLI input overrides WW_CORE_JSON_INPUT. With neither set, core.json in the
 * process working directory is selected. Version requests are printed here and
 * returned as an early successful exit.
 *
 * @param argc Process argument count.
 * @param argv Process argument vector.
 * @param options Parsed options for a normal runtime start.
 * @return Whether startup should run, exit successfully, or exit with failure.
 */
waterwall_startup_arguments_result_e waterwallStartupOptionsParse(int argc, char *const argv[],
                                                                  waterwall_startup_options_t *options);

/**
 * @brief Read the selected core JSON source into a null-terminated buffer.
 *
 * Call this after initWLibc(). The caller owns the returned buffer and releases
 * it with memoryFree().
 *
 * @param options Parsed startup options.
 * @return Core JSON contents, or NULL after reporting a clear input error.
 */
char *waterwallStartupOptionsReadCoreJson(const waterwall_startup_options_t *options);

/**
 * @brief Report that the selected input was read but was not valid core JSON.
 *
 * @param options Parsed startup options.
 */
void waterwallStartupOptionsReportCoreJsonParseFailure(const waterwall_startup_options_t *options);
