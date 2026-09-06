#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

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
        bool        restricted_config;
    } waterwall_startup_options_t;

    typedef struct waterwall_handoff_s
    {
        bool        has_handoff;
        int         fd;
        uintptr_t   mapping; /* Windows snapshot handle; never a CRT descriptor. */
        size_t      length;
        const char *source_name;
        const char *orig_exe;
    } waterwall_handoff_t;

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
     * Available before runtime initialization. The caller owns the returned buffer
     * and releases it with waterwallStartupOptionsFreeCoreJson().
     *
     * @param options Parsed startup options.
     * @param out_length Optional pointer to receive the read length.
     * @return Core JSON contents, or NULL after reporting a clear input error.
     */
    char *waterwallStartupOptionsReadCoreJson(const waterwall_startup_options_t *options, size_t *out_length);

    /**
     * @brief Release memory returned by waterwallStartupOptionsReadCoreJson().
     *
     * @param content Buffer to free.
     */
    void waterwallStartupOptionsFreeCoreJson(char *content);

    /**
     * @brief Report that the selected input was read but was not valid core JSON.
     *
     * @param options Parsed startup options.
     */
    void waterwallStartupOptionsReportCoreJsonParseFailure(const waterwall_startup_options_t *options);

    /**
     * @brief Extract reserved internal handoff arguments from argv.
     *
     * Scans argv for --ww-internal-fd (Windows: --ww-internal-map), --ww-internal-len, --ww-internal-src, and
     * --ww-internal-exe. If found, validates them, strips them from argv, updates *argc, and populates handoff. Path
     * strings borrow argv storage. Returns 1 if valid handoff was found, 0 if no handoff arguments were present, or -1
     * if handoff arguments were incomplete, duplicate, or malformed.
     */
    int waterwallStartupHandoffExtract(int *argc, char **argv, waterwall_handoff_t *handoff);

    /**
     * @brief Read configuration snapshot from the platform handoff.
     *
     * Validates descriptor range/accessibility, sets FD_CLOEXEC, reads exact length,
     * and closes the descriptor. Windows validates a read-only mapping and its
     * transport header, copies exact bytes, and closes the handle.
     * Returns 0 on success, -1 on failure.
     */
    int waterwallStartupHandoffReceive(waterwall_handoff_t *handoff, bool restricted, char **out_content,
                                       size_t *out_length);

    /**
     * @brief Clean up handoff resources and metadata.
     */
    void waterwallStartupHandoffCleanup(waterwall_handoff_t *handoff);

#ifdef __cplusplus
}
#endif
