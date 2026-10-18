#pragma once

/*
 * Config file loader and safe commit helpers for runtime node configuration.
 */

#include "wlibc.h"
#include "wmutex.h"

/* api_selector_strings_invalid retains raw string evidence before cJSON loses
 * lengths. It is enforced only when the loaded process contains an APIServer. */
typedef struct config_file_s
{
    char         *file_path;
    char         *name;
    char         *author;
    int           config_version;
    int           core_minimum_version;
    bool          encrypted;
    bool          api_selector_strings_invalid;
    struct cJSON *root;
    struct cJSON *nodes;
    size_t        file_prebuffer_size;
    wmutex_t      guard;
} config_file_t;

// a config is loaded in ram and can be updated continously by other threads forexample when a user
// uses some traffic, at some point the config file will be updated, the live data however is available through the api
// so , i see no reason to destroy a config file...
/**
 * @brief Destroy a parsed config file object and release all owned resources.
 *
 * @param state Config object.
 */
void destroyConfigFile(config_file_t *state);

/**
 * @brief Acquire config update mutex.
 *
 * @param state Config object.
 */
void acquireUpdateLock(config_file_t *state);

/**
 * @brief Release config update mutex.
 *
 * @param state Config object.
 */
void releaseUpdateLock(config_file_t *state);
// only use if you acquired lock before
/**
 * @brief Persist config JSON to disk without taking the lock.
 *
 * @param state Config object (caller must hold lock).
 */
void unsafeCommitChanges(config_file_t *state);

/**
 * @brief Persist config changes to disk while holding the lock.
 *
 * @param state Config object.
 */
void commitChangesHard(config_file_t *state);
// will not write if the mutex is locked
/**
 * @brief Try to persist config changes only if lock is immediately available.
 *
 * @param state Config object.
 */
void commitChangesSoft(config_file_t *state);

/**
 * @brief Parse a JSON config file into a mutable runtime config object.
 *
 * @param file_path Path to config file.
 * @return config_file_t* Parsed config, or NULL on error.
 */
config_file_t *configfileParse(const char *file_path);

/**
 * @brief Destroy a config object.
 *
 * @param cf Config object.
 */
void configfileDestroy(config_file_t * cf);
