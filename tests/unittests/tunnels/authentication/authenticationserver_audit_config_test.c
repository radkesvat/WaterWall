/* CTest: waterwall.authenticationserver_audit_config_unit
 * Actual settings parser and writer startup; protected files stay untouched. */
#include "AuthenticationServer/structure.h"
#include "fixtures/assertions.h"
#include "loggers/network_logger.h"

static const char *audit_config_name = "main";
static char        audit_node_name[] = "authentication";
static node_t      audit_node        = {.name = audit_node_name};
static tunnel_t   *audit_tunnel;

static char audit_diagnostic[2048];

static void auditCaptureDiagnostic(int level, const char *text, int length)
{
    if (level < LOG_LEVEL_ERROR)
        return;
    size_t copied = min((size_t) max(length, 0), sizeof(audit_diagnostic) - 1U);
    memoryCopy(audit_diagnostic, text, copied);
    audit_diagnostic[copied] = '\0';
}

const char *__wrap_nodemanagerConfigName(const node_manager_config_t *config);
const char *__wrap_nodemanagerConfigName(const node_manager_config_t *config)
{
    discard config;
    return audit_config_name;
}

static void auditConfigExpect(const char *text, const char *path, bool accepted, bool enabled)
{
    char json[8192];
    int  count = snprintf(json, sizeof(json), text, path);
    twfRequire(count > 0 && count < (int) sizeof(json), "audit settings fixture overflow");
    audit_node.node_settings_json = cJSON_Parse(json);
    twfRequire(audit_node.node_settings_json != NULL, "audit fixture JSON invalid");
    audit_diagnostic[0]               = '\0';
    authenticationserver_tstate_t *ts = tunnelGetState(audit_tunnel);
    twfRequire(authenticationserverAuditConfigure(audit_tunnel, &audit_node) == accepted &&
                   (ts->audit != NULL) == enabled,
               "audit configuration acceptance mismatch");
    if (ts->audit != NULL)
        authenticationserverAuditDestroy(ts->audit);
    ts->audit = NULL;
    cJSON_Delete(audit_node.node_settings_json);
    audit_node.node_settings_json = NULL;
}

static void auditConfigExpectDiagnostic(const char *text, const char *path, const char *category)
{
    auditConfigExpect(text, path, false, false);
    twfRequire(strstr(audit_diagnostic, category) != NULL, "audit refusal diagnostic category mismatch");
}

static void auditConfigProtected(const char *path, bool create)
{
    static const char content[] = "DATABASE MUST REMAIN\n";
    int               fd        = open(path, create ? O_WRONLY | O_CREAT | O_EXCL : O_RDONLY, 0644);
    twfRequire(fd >= 0, "protected audit fixture open failed");
    if (create)
        twfRequire(write(fd, content, sizeof(content) - 1) == sizeof(content) - 1 && fchmod(fd, 0644) == 0,
                   "protected audit fixture write failed");
    else
    {
        char        actual[sizeof(content)] = {0};
        struct stat info;
        twfRequire(read(fd, actual, sizeof(actual)) == sizeof(content) - 1 && strcmp(actual, content) == 0 &&
                       fstat(fd, &info) == 0 && (info.st_mode & 0777) == 0644,
                   "audit configuration changed protected file contents or permissions");
    }
    twfRequire(close(fd) == 0, "protected audit fixture close failed");
}

int main(void)
{
    twfRequire(createNetworkLogger(NULL, false) != NULL, "audit config logger init failed");
    loggerSetHandler(getNetworkLogger(), auditCaptureDiagnostic);
    char directory[] = "/tmp/waterwall-audit-config-XXXXXX";
    twfRequire(mkdtemp(directory) != NULL, "audit config directory failed");
    char path[512], database[512], backup[512], other[1024];
    snprintf(path, sizeof(path), "%s/admin.jsonl", directory);
    snprintf(database, sizeof(database), "%s/users.json", directory);
    snprintf(backup, sizeof(backup), "%s/users.backup", directory);
    auditConfigProtected(database, true);
    auditConfigProtected(backup, true);
    audit_tunnel = tunnelCreate(&audit_node, sizeof(authenticationserver_tstate_t), 0);
    twfRequire(audit_tunnel != NULL, "audit config tunnel init failed");
    authenticationserver_tstate_t *ts = tunnelGetState(audit_tunnel);
    ts->db_path                       = database;
    ts->backup_path                   = backup;
    const char *valid                 = "{\"audit-log\":{\"path\":\"%s\"}}";
    auditConfigExpect("{}", path, true, false);
    auditConfigExpect(valid, path, true, true);
    auditConfigExpect("{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":16384,\"max-files\":2}}", path, true, true);
    auditConfigExpect(
        "{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":1073741824,\"max-files\":32}}", path, true, true);
    static const char *invalid[] = {"{\"audit-log\":false}",
                                    "{\"audit-log\":null}",
                                    "{\"audit-log\":[]}",
                                    "{\"audit-log\":{}}",
                                    "{\"audit-log\":{\"path\":\"\"}}",
                                    "{\"audit-log\":{\"path\":1}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"path\":\"ignored\"}}",
                                    "{\"audit-log\":{\"path\":\"%s\"},\"audit-log\":{}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"level\":\"info\"}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":16383}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":1073741825}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":16384.5}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":\"16384\"}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-file-size\":16384,\"max-file-size\":16384}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-files\":1}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-files\":33}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-files\":2.5}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-files\":\"2\"}}",
                                    "{\"audit-log\":{\"path\":\"%s\",\"max-files\":2,\"max-files\":2}}"};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
        auditConfigExpect(invalid[i], path, false, false);
    char long_path[MAX_PATH];
    memset(long_path, 'a', sizeof(long_path) - 1);
    long_path[sizeof(long_path) - 1] = '\0';
    auditConfigExpectDiagnostic(valid, long_path, "supported bounds");
    snprintf(other, sizeof(other), "%s/missing/audit", directory);
    auditConfigExpectDiagnostic(valid, other, "parent resolution failed");
    char label[kAuthenticationServerAuditLabelCap + 2];
    memset(label, 'x', sizeof(label) - 1);
    label[sizeof(label) - 1] = '\0';
    audit_config_name        = label;
    auditConfigExpect(valid, path, false, false);
    audit_config_name = "";
    auditConfigExpect(valid, path, false, false);
    audit_config_name = "\xff";
    auditConfigExpect(valid, path, false, false);
    audit_config_name = "main";
    audit_node.name   = label;
    auditConfigExpect(valid, path, false, false);
    audit_node.name                             = audit_node_name;
    authenticationserver_auth_client_t producer = {.name = label};
    ts->auth_clients                            = &producer;
    ts->auth_clients_count                      = 1;
    auditConfigExpect(valid, path, false, false);
    label[kAuthenticationServerAuditLabelCap] = '\0';
    audit_config_name                         = label;
    audit_node.name                           = label;
    auditConfigExpect(valid, path, true, true);
    audit_config_name      = "main";
    audit_node.name        = audit_node_name;
    ts->auth_clients_count = 0;
    ts->auth_clients       = NULL;
    auditConfigExpectDiagnostic(valid, database, "overlap database");
    auditConfigExpectDiagnostic(valid, backup, "overlap database");
    snprintf(other, sizeof(other), "%s/../%s/users.json", directory, strrchr(directory, '/') + 1);
    auditConfigExpect(valid, other, false, false);
    snprintf(other, sizeof(other), "%s/hardlink.jsonl", directory);
    twfRequire(link(database, other) == 0, "audit hardlink setup failed");
    auditConfigExpectDiagnostic(valid, other, "overlap database");
    twfRequire(unlink(other) == 0, "audit hardlink cleanup failed");
    snprintf(other, sizeof(other), "%s/alias", directory);
    twfRequire(symlink(directory, other) == 0, "audit directory alias setup failed");
    snprintf(other, sizeof(other), "%s/alias/users.json", directory);
    auditConfigExpect(valid, other, false, false);

    /* History snapshots replace/prune authenticationserver-*.json. Audit paths
     * cannot take that namespace, including through a directory alias, while a
     * regular JSONL audit file in the same directory remains supported. */
    ts->normal_backups_path = directory;
    snprintf(other, sizeof(other), "%s/authenticationserver-users-history.json", directory);
    auditConfigProtected(other, true);
    auditConfigExpect(valid, other, false, false);
    auditConfigProtected(other, false);
    snprintf(other, sizeof(other), "%s/alias/authenticationserver-users-history.json", directory);
    auditConfigExpect(valid, other, false, false);
    auditConfigExpect(valid, path, true, true);
    snprintf(other, sizeof(other), "%s/alias", directory);
    ts->normal_backups_path = other;
    char history[512];
    snprintf(history, sizeof(history), "%s/authenticationserver-users-history.json", directory);
    auditConfigExpect(valid, history, false, false);
    auditConfigProtected(history, false);
    ts->normal_backups_path = NULL;

    /* A short configured alias may resolve beyond WaterWall's path limit.
     * realpath must have PATH_MAX storage before rejecting that resolved name. */
    char deep[4][512], component[121];
    memset(component, 'd', sizeof(component) - 1);
    component[sizeof(component) - 1] = '\0';
    snprintf(deep[0], sizeof(deep[0]), "%s/deep", directory);
    twfRequire(mkdir(deep[0], 0700) == 0, "audit deep parent setup failed");
    for (unsigned i = 1; i < 4; ++i)
    {
        size_t prefix = strlen(deep[i - 1]);
        twfRequire(prefix + 1 + sizeof(component) <= sizeof(deep[i]), "audit long parent fixture overflow");
        memcpy(deep[i], deep[i - 1], prefix);
        deep[i][prefix] = '/';
        memcpy(deep[i] + prefix + 1, component, sizeof(component));
        twfRequire(mkdir(deep[i], 0700) == 0, "audit long parent setup failed");
    }
    twfRequire(strlen(deep[3]) > MAX_PATH, "audit resolved parent did not exceed path limit");
    snprintf(other, sizeof(other), "%s/deep-alias", directory);
    twfRequire(symlink(deep[3], other) == 0, "audit long parent alias setup failed");
    snprintf(other, sizeof(other), "%s/deep-alias/admin.jsonl", directory);
    auditConfigExpectDiagnostic(valid, other, "supported bounds");
    snprintf(other, sizeof(other), "%s/admin.jsonl", deep[3]);
    twfRequire(access(other, F_OK) != 0 && errno == ENOENT, "audit created a file under an oversized parent");
    snprintf(other, sizeof(other), "%s/admin.jsonl.lock", deep[3]);
    twfRequire(access(other, F_OK) != 0 && errno == ENOENT, "audit created a lock under an oversized parent");
    char deep_alias[512];
    snprintf(deep_alias, sizeof(deep_alias), "%s/deep-alias", directory);
    ts->normal_backups_path = deep_alias;
    snprintf(other, sizeof(other), "%s/authenticationserver-history.json", directory);
    auditConfigExpectDiagnostic(valid, other, "supported bounds");
    twfRequire(access(other, F_OK) != 0 && errno == ENOENT, "failed history-path check created an audit file");
    ts->normal_backups_path = NULL;
    snprintf(other, sizeof(other), "%s/deep-alias/users.json", directory);
    ts->db_path = other;
    auditConfigExpectDiagnostic(valid, path, "supported bounds");
    ts->db_path = database;
    for (unsigned i = 4; i > 0; --i)
        twfRequire(rmdir(deep[i - 1]) == 0, "audit long parent cleanup failed");

    /* The configured spelling fits, but its lock/archive candidates must fit too. */
    size_t prefix_length = strlen(directory);
    memoryCopy(other, directory, prefix_length);
    other[prefix_length] = '/';
    memset(other + prefix_length + 1, 's', MAX_PATH - 17U - prefix_length - 1U);
    other[MAX_PATH - 17U] = '\0';
    auditConfigExpectDiagnostic(valid, other, "supported bounds");
    twfRequire(access(other, F_OK) != 0 && errno == ENOENT, "audit suffix refusal created a file");

    for (unsigned i = 0; i < 2; ++i)
    {
        snprintf(other, sizeof(other), "%s%s", path, i == 0 ? ".1" : ".lock");
        twfRequire(unlink(other) == 0 || errno == ENOENT, "audit collision fixture cleanup failed");
        auditConfigProtected(other, true);
        ts->db_path = other;
        auditConfigExpect(valid, path, false, false);
        auditConfigProtected(other, false);
    }
    auditConfigProtected(database, false);
    auditConfigProtected(backup, false);
    tunnelDestroy(audit_tunnel);
    networkloggerDestroy();
    DIR *dir = opendir(directory);
    twfRequire(dir != NULL, "audit config cleanup open failed");
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL)
    {
        if (entry->d_name[0] == '.')
            continue;
        snprintf(other, sizeof(other), "%s/%s", directory, entry->d_name);
        twfRequire(unlink(other) == 0, "audit config cleanup unlink failed");
    }
    twfRequire(closedir(dir) == 0 && rmdir(directory) == 0, "audit config cleanup failed");
    return 0;
}
