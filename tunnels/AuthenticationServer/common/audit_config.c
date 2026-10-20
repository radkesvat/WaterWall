#include "AuthenticationServer/structure.h"
#include "loggers/network_logger.h"
#include "managers/node_manager.h"
#include "node_builder/config_lexical.h"

typedef enum authenticationserver_audit_path_result_e
{
    kAuditPathValid,
    kAuditPathUnsupported,
    kAuditPathParentUnavailable,
    kAuditPathOverlap,
    kAuditPathHistoryOverlap
} authenticationserver_audit_path_result_t;

/* Resolve the parent as well as the basename: two relative spellings or directory
 * aliases must not let audit rotation overwrite this node's database/backup. */
static authenticationserver_audit_path_result_t authenticationserverAuditCanonicalPath(const char *path,
                                                                                       char        output[MAX_PATH])
{
    if (path == NULL || path[0] == '\0' || strlen(path) >= MAX_PATH - 16)
        return kAuditPathUnsupported;
    char parent[MAX_PATH];
    memoryCopy(parent, path, strlen(path) + 1);
    char *base = parent;
    for (char *cursor = parent; *cursor != '\0'; ++cursor)
        if (filePathIsSeparator(*cursor))
            base = cursor + 1;
    if (*base == '\0' || strcmp(base, ".") == 0 || strcmp(base, "..") == 0)
        return kAuditPathUnsupported;
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
        return kAuditPathParentUnavailable;
    const DWORD length = GetFinalPathNameByHandleA(directory, resolved, sizeof(resolved), FILE_NAME_NORMALIZED);
    CloseHandle(directory);
    if (length == 0)
        return kAuditPathParentUnavailable;
    if (length >= sizeof(resolved))
        return kAuditPathUnsupported;
#else
    char resolved[PATH_MAX];
    if (realpath(parent, resolved) == NULL)
        return errno == ENAMETOOLONG ? kAuditPathUnsupported : kAuditPathParentUnavailable;
#endif
    const int count = snprintf(output, MAX_PATH, "%s/%s", resolved, leaf);
    return count > 0 && count < MAX_PATH ? kAuditPathValid : kAuditPathUnsupported;
}

static authenticationserver_audit_path_result_t authenticationserverAuditPathConflicts(const char *left,
                                                                                       const char *right)
{
    if (right == NULL)
        return kAuditPathValid;
    char                                     canonical_left[MAX_PATH], canonical_right[MAX_PATH];
    authenticationserver_audit_path_result_t result = authenticationserverAuditCanonicalPath(left, canonical_left);
    if (result != kAuditPathValid)
        return result;
    result = authenticationserverAuditCanonicalPath(right, canonical_right);
    if (result != kAuditPathValid)
        return result;
#ifdef OS_WIN
    if (_stricmp(canonical_left, canonical_right) == 0)
        return kAuditPathOverlap;
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
    return same ? kAuditPathOverlap : kAuditPathValid;
#else
    if (strcmp(canonical_left, canonical_right) == 0)
        return kAuditPathOverlap;
    struct stat first, second;
    return stat(left, &first) == 0 && stat(right, &second) == 0 && first.st_dev == second.st_dev &&
                   first.st_ino == second.st_ino
               ? kAuditPathOverlap
               : kAuditPathValid;
#endif
}

/* The history saver replaces and prunes this filename namespace independently
 * of the audit writer. Keep active audit files outside it, including aliases. */
static authenticationserver_audit_path_result_t authenticationserverAuditHistoryPathConflicts(
    const char *path, const char *history_directory)
{
    if (history_directory == NULL)
        return kAuditPathValid;
    const char       *basename = filePathBaseName(path);
    static const char prefix[] = "authenticationserver-";
    const size_t      length   = strlen(basename);
    if (length < sizeof(prefix) - 1 + sizeof(".json") - 1)
        return kAuditPathValid;
#ifdef OS_WIN
    if (_strnicmp(basename, prefix, sizeof(prefix) - 1) != 0 || _stricmp(basename + length - 5, ".json") != 0)
#else
    if (strncmp(basename, prefix, sizeof(prefix) - 1) != 0 || strcmp(basename + length - 5, ".json") != 0)
#endif
        return kAuditPathValid;
    char history_child[MAX_PATH], canonical_history[MAX_PATH], canonical_audit[MAX_PATH];
    int  count = snprintf(history_child, sizeof(history_child), "%s/.audit-parent", history_directory);
    if (count <= 0 || (size_t) count >= sizeof(history_child))
        return kAuditPathUnsupported;
    authenticationserver_audit_path_result_t result =
        authenticationserverAuditCanonicalPath(history_child, canonical_history);
    if (result != kAuditPathValid)
        return result;
    result = authenticationserverAuditCanonicalPath(path, canonical_audit);
    if (result != kAuditPathValid)
        return result;
    /* CanonicalPath always joins the resolved parent and basename with '/'. */
    *strrchr(canonical_history, '/') = '\0';
    *strrchr(canonical_audit, '/')   = '\0';
#ifdef OS_WIN
    return _stricmp(canonical_history, canonical_audit) == 0 ? kAuditPathHistoryOverlap : kAuditPathValid;
#else
    return strcmp(canonical_history, canonical_audit) == 0 ? kAuditPathHistoryOverlap : kAuditPathValid;
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
    if (path == NULL || path[0] == '\0' || ! configLexicalCheckEncoding(path, strlen(path)))
        goto invalid;
    authenticationserver_audit_path_result_t path_result = kAuditPathValid;
    if (strlen(path) >= MAX_PATH - 16)
    {
        path_result = kAuditPathUnsupported;
        goto invalid_path;
    }
    const char *config_name = nodemanagerConfigName(node->node_manager_config);
    if (! authenticationserverAuditLabelValid(config_name) || ! authenticationserverAuditLabelValid(node->name))
        goto invalid;
    for (uint32_t i = 0; i < ts->auth_clients_count; ++i)
        if (! authenticationserverAuditLabelValid(ts->auth_clients[i].name))
            goto invalid;
    for (unsigned i = 0; i <= max_files; ++i)
    {
        char candidate[MAX_PATH];
        int  count;
        if (i == 0)
            count = snprintf(candidate, sizeof(candidate), "%s", path);
        else if (i == max_files)
            count = snprintf(candidate, sizeof(candidate), "%s.lock", path);
        else
            count = snprintf(candidate, sizeof(candidate), "%s.%u", path, i);
        if (count <= 0 || (size_t) count >= sizeof(candidate))
        {
            path_result = kAuditPathUnsupported;
            goto invalid_path;
        }
        /* Validate each archive and lock candidate even without DB paths. */
        char canonical[MAX_PATH];
        path_result = authenticationserverAuditCanonicalPath(candidate, canonical);
        if (path_result == kAuditPathValid)
            path_result = authenticationserverAuditPathConflicts(candidate, ts->db_path);
        if (path_result == kAuditPathValid)
            path_result = authenticationserverAuditPathConflicts(candidate, ts->backup_path);
        if (path_result != kAuditPathValid)
            goto invalid_path;
    }
    path_result = authenticationserverAuditHistoryPathConflicts(path, ts->normal_backups_path);
    if (path_result != kAuditPathValid)
        goto invalid_path;
    ts->audit =
        authenticationserverAuditCreate(path, max_size, max_files, config_name, node->name, ts->api_instance_id);
    return ts->audit != NULL;

invalid_path:
    switch (path_result)
    {
    case kAuditPathUnsupported:
        LOGE("AuthenticationServer: audit path exceeds supported bounds or has an unsupported basename");
        break;
    case kAuditPathParentUnavailable:
        LOGE("AuthenticationServer: audit path parent resolution failed");
        break;
    case kAuditPathHistoryOverlap:
        LOGE("AuthenticationServer: audit paths must not use the authenticationserver-*.json history namespace "
             "inside normal-backups-path");
        break;
    default:
        LOGE("AuthenticationServer: audit paths must not overlap database or recovery files");
        break;
    }
    return false;

invalid:
    LOGE("AuthenticationServer: invalid audit-log settings or audit identity; require a path, bounded integer "
         "rotation limits, and logical configuration/node/producer names of 1..256 UTF-8 bytes");
    return false;
}
