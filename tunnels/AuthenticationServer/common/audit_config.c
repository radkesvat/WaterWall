#include "AuthenticationServer/structure.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "node_builder/config_lexical.h"

/* Resolve the parent as well as the basename: two relative spellings or directory
 * aliases must not let audit rotation overwrite this node's database/backup. */
static bool authenticationserverAuditCanonicalPath(const char *path, char output[MAX_PATH])
{
    if (path == NULL || path[0] == '\0' || strlen(path) >= MAX_PATH - 16)
        return false;
    char parent[MAX_PATH];
    memoryCopy(parent, path, strlen(path) + 1);
    char *base = parent;
    for (char *cursor = parent; *cursor != '\0'; ++cursor)
        if (filePathIsSeparator(*cursor))
            base = cursor + 1;
    if (*base == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        return false;
    char leaf[MAX_PATH];
    memoryCopy(leaf, base, strlen(base) + 1);
    if (base == parent)
        strcpy(parent, ".");
    else
        *base = '\0';
#ifdef OS_WIN
    char   resolved[MAX_PATH];
    HANDLE directory = CreateFileA(parent,
                                   0,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                   NULL,
                                   OPEN_EXISTING,
                                   FILE_FLAG_BACKUP_SEMANTICS,
                                   NULL);
    if (directory == INVALID_HANDLE_VALUE)
        return false;
    const DWORD length = GetFinalPathNameByHandleA(directory, resolved, sizeof(resolved), FILE_NAME_NORMALIZED);
    CloseHandle(directory);
    if (length == 0 || length >= sizeof(resolved))
        return false;
#else
    char resolved[PATH_MAX];
    if (realpath(parent, resolved) == NULL)
        return false;
#endif
    const int count = snprintf(output, MAX_PATH, "%s/%s", resolved, leaf);
    return count > 0 && count < MAX_PATH;
}

static bool authenticationserverAuditPathConflicts(const char *left, const char *right)
{
    if (right == NULL)
        return false;
    char canonical_left[MAX_PATH], canonical_right[MAX_PATH];
    if (! authenticationserverAuditCanonicalPath(left, canonical_left) ||
        ! authenticationserverAuditCanonicalPath(right, canonical_right))
        return true;
#ifdef OS_WIN
    if (_stricmp(canonical_left, canonical_right) == 0)
        return true;
    HANDLE                     first  = CreateFileA(left,
                               FILE_READ_ATTRIBUTES,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               NULL,
                               OPEN_EXISTING,
                               FILE_FLAG_OPEN_REPARSE_POINT,
                               NULL);
    HANDLE                     second = CreateFileA(right,
                                FILE_READ_ATTRIBUTES,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                NULL,
                                OPEN_EXISTING,
                                FILE_FLAG_OPEN_REPARSE_POINT,
                                NULL);
    BY_HANDLE_FILE_INFORMATION a, b;
    bool                       same = first != INVALID_HANDLE_VALUE && second != INVALID_HANDLE_VALUE &&
                GetFileInformationByHandle(first, &a) && GetFileInformationByHandle(second, &b) &&
                a.dwVolumeSerialNumber == b.dwVolumeSerialNumber && a.nFileIndexHigh == b.nFileIndexHigh &&
                a.nFileIndexLow == b.nFileIndexLow;
    if (first != INVALID_HANDLE_VALUE)
        CloseHandle(first);
    if (second != INVALID_HANDLE_VALUE)
        CloseHandle(second);
    return same;
#else
    if (strcmp(canonical_left, canonical_right) == 0)
        return true;
    struct stat first, second;
    return stat(left, &first) == 0 && stat(right, &second) == 0 && first.st_dev == second.st_dev &&
           first.st_ino == second.st_ino;
#endif
}

/* The history saver replaces and prunes this filename namespace independently
 * of the audit writer. Keep active audit files outside it, including aliases. */
static bool authenticationserverAuditHistoryPathConflicts(const char *path, const char *history_directory)
{
    if (history_directory == NULL)
        return false;
    const char       *basename = filePathBaseName(path);
    static const char prefix[] = "authenticationserver-";
    const size_t      length   = strlen(basename);
    if (length < sizeof(prefix) - 1 + sizeof(".json") - 1)
        return false;
#ifdef OS_WIN
    if (_strnicmp(basename, prefix, sizeof(prefix) - 1) != 0 || _stricmp(basename + length - 5, ".json") != 0)
#else
    if (strncmp(basename, prefix, sizeof(prefix) - 1) != 0 || strcmp(basename + length - 5, ".json") != 0)
#endif
        return false;
    char history_child[MAX_PATH], canonical_history[MAX_PATH], canonical_audit[MAX_PATH];
    int  count = snprintf(history_child, sizeof(history_child), "%s/.audit-parent", history_directory);
    if (count <= 0 || (size_t) count >= sizeof(history_child) ||
        ! authenticationserverAuditCanonicalPath(history_child, canonical_history) ||
        ! authenticationserverAuditCanonicalPath(path, canonical_audit))
        return true;
    /* CanonicalPath always joins the resolved parent and basename with '/'. */
    *strrchr(canonical_history, '/') = '\0';
    *strrchr(canonical_audit, '/')   = '\0';
#ifdef OS_WIN
    return _stricmp(canonical_history, canonical_audit) == 0;
#else
    return strcmp(canonical_history, canonical_audit) == 0;
#endif
}

static bool authenticationserverAuditLabelValid(const char *text)
{
    if (text == NULL)
        return false;
    const size_t length = strlen(text);
    return length > 0 && length <= kAuthenticationServerAuditLabelCap && configLexicalCheckEncoding(text, length);
}

bool authenticationserverAuditConfigure(tunnel_t *t, node_t *node)
{
    authenticationserver_tstate_t *ts       = tunnelGetState(t);
    const cJSON                   *settings = node->node_settings_json;
    const cJSON                   *audit    = NULL;
    const cJSON                   *field;
    cJSON_ArrayForEach(field, settings)
    {
        if (strcmp(field->string, "audit-log") == 0)
        {
            if (audit != NULL)
                goto invalid;
            audit = field;
        }
    }
    if (audit == NULL)
        return true;
    if (! cJSON_IsObject(audit))
        goto invalid;
    const char *path      = NULL;
    uint64_t    max_size  = 16U * 1024U * 1024U;
    unsigned    max_files = 7;
    unsigned    seen      = 0;
    cJSON_ArrayForEach(field, audit)
    {
        unsigned bit;
        if (strcmp(field->string, "path") == 0)
        {
            bit = 1;
            if (! cJSON_IsString(field) || field->valuestring == NULL)
                goto invalid;
            path = field->valuestring;
        }
        else if (strcmp(field->string, "max-file-size") == 0)
        {
            bit = 2;
            if (! cJSON_IsNumber(field) || field->valuedouble < kAuthenticationServerAuditRecordCap ||
                field->valuedouble > 1073741824.0 || field->valuedouble != (double) field->valueint)
                goto invalid;
            max_size = (uint64_t) field->valueint;
        }
        else if (strcmp(field->string, "max-files") == 0)
        {
            bit = 4;
            if (! cJSON_IsNumber(field) || field->valueint < 2 || field->valueint > 32 ||
                field->valuedouble != (double) field->valueint)
                goto invalid;
            max_files = (unsigned) field->valueint;
        }
        else
            goto invalid;
        if ((seen & bit) != 0)
            goto invalid;
        seen |= bit;
    }
    if (path == NULL || path[0] == '\0' || strlen(path) >= MAX_PATH - 16 ||
        ! configLexicalCheckEncoding(path, strlen(path)))
        goto invalid;
    const char *config_name = nodemanagerConfigName(node->node_manager_config);
    if (! authenticationserverAuditLabelValid(config_name) || ! authenticationserverAuditLabelValid(node->name))
        goto invalid;
    for (uint32_t i = 0; i < ts->auth_clients_count; ++i)
        if (! authenticationserverAuditLabelValid(ts->auth_clients[i].name))
            goto invalid;
    for (unsigned i = 0; i <= max_files; ++i)
    {
        char candidate[MAX_PATH];
        if (i == 0)
            snprintf(candidate, sizeof(candidate), "%s", path);
        else if (i == max_files)
            snprintf(candidate, sizeof(candidate), "%s.lock", path);
        else
            snprintf(candidate, sizeof(candidate), "%s.%u", path, i);
        if (authenticationserverAuditPathConflicts(candidate, ts->db_path) ||
            authenticationserverAuditPathConflicts(candidate, ts->backup_path))
        {
            LOGE("AuthenticationServer: audit file parents must exist and audit paths must not overlap database "
                 "or recovery files");
            return false;
        }
    }
    if (authenticationserverAuditHistoryPathConflicts(path, ts->normal_backups_path))
    {
        LOGE("AuthenticationServer: audit paths must not use the authenticationserver-*.json history namespace "
             "inside normal-backups-path");
        return false;
    }
    ts->audit =
        authenticationserverAuditCreate(path, max_size, max_files, config_name, node->name, ts->api_instance_id);
    return ts->audit != NULL;

invalid:
    LOGE("AuthenticationServer: invalid audit-log settings or audit identity; require a path, bounded integer "
         "rotation limits, and logical configuration/node/producer names of 1..256 UTF-8 bytes");
    return false;
}
