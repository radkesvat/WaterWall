#include "syslog.h"

enum
{
    kSyslogFacilityKernel = 0,
    kSyslogFacilityDaemon = 3,
    kSyslogFacilityAuth   = 4,
    kSyslogFacilitySyslog = 5,
    kSyslogFacilityCron   = 9,
    kSyslogFacilityLocal0 = 16,
    kSyslogFacilityLocal7 = 23,

    kSyslogSeverityInfo    = 6,
    kSyslogSeverityNotice  = 5,
    kSyslogSeverityWarning = 4,
    kSyslogSeverityError   = 3,
};

typedef struct junkdatagramsender_syslog_event_s
{
    const char *app;
    const char *msgid;
    const char *message;
    uint8_t     facility;
    uint8_t     severity;
} junkdatagramsender_syslog_event_t;

static uint32_t junkdatagramsenderSyslogWriteLimit(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t limit = sbufGetMaximumWriteableSize(buf);
    if (args != NULL && args->max_packet_size > 0 && args->max_packet_size < limit)
    {
        limit = args->max_packet_size;
    }
    return limit;
}

static const char *junkdatagramsenderSyslogRandomHost(char *buf, size_t buf_len)
{
    static const char *prefixes[] = {
        "router",
        "switch",
        "server",
        "host",
        "edge",
        "gateway",
        "node",
        "ww",
    };

    if (stringFormatFits(
            stringNPrintf(buf,
                          buf_len,
                          "%s-%02u",
                          prefixes[fastRand32() % (sizeof(prefixes) / sizeof(prefixes[0]))],
                          (unsigned int) (fastRand32() % 100U)),
            (uint32_t) buf_len))
    {
        return buf;
    }
    return "host";
}

static const junkdatagramsender_syslog_event_t *junkdatagramsenderSyslogRandomEvent(void)
{
    static const junkdatagramsender_syslog_event_t events[] = {
        {.app      = "sshd",
         .msgid    = "AUTH",
         .message  = "Accepted publickey for admin from 192.0.2.42 port 54122 ssh2",
         .facility = kSyslogFacilityAuth,
         .severity = kSyslogSeverityInfo},
        {.app      = "sshd",
         .msgid    = "AUTH",
         .message  = "Failed password for invalid user test from 198.51.100.17 port 41812 ssh2",
         .facility = kSyslogFacilityAuth,
         .severity = kSyslogSeverityWarning},
        {.app      = "sudo",
         .msgid    = "USER_CMD",
         .message  = "admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/systemctl status nginx",
         .facility = kSyslogFacilityAuth,
         .severity = kSyslogSeverityNotice},
        {.app      = "kernel",
         .msgid    = "LINK",
         .message  = "eth0: link up, 1000Mbps, full-duplex",
         .facility = kSyslogFacilityKernel,
         .severity = kSyslogSeverityInfo},
        {.app      = "systemd",
         .msgid    = "UNIT",
         .message  = "Started Network Manager Script Dispatcher Service.",
         .facility = kSyslogFacilityDaemon,
         .severity = kSyslogSeverityInfo},
        {.app      = "cron",
         .msgid    = "CMD",
         .message  = "(root) CMD (/usr/lib/sa/sa1 1 1)",
         .facility = kSyslogFacilityCron,
         .severity = kSyslogSeverityInfo},
        {.app      = "dhclient",
         .msgid    = "LEASE",
         .message  = "DHCPREQUEST for 192.168.1.42 on eth0 to 192.168.1.1 port 67",
         .facility = kSyslogFacilityDaemon,
         .severity = kSyslogSeverityInfo},
        {.app      = "named",
         .msgid    = "DNS",
         .message  = "client @0x7f query: api.office.lan IN A + (192.0.2.53)",
         .facility = kSyslogFacilityDaemon,
         .severity = kSyslogSeverityInfo},
        {.app      = "nginx",
         .msgid    = "ACCESS",
         .message  = "192.0.2.10 - - \"GET /health HTTP/1.1\" 200 2 \"-\" \"curl/8.0\"",
         .facility = kSyslogFacilityLocal0,
         .severity = kSyslogSeverityInfo},
        {.app      = "snmpd",
         .msgid    = "SNMP",
         .message  = "Connection from UDP: [198.51.100.20]:53421->[192.0.2.10]:161",
         .facility = kSyslogFacilityDaemon,
         .severity = kSyslogSeverityInfo},
        {.app      = "syslogd",
         .msgid    = "MARK",
         .message  = "-- MARK --",
         .facility = kSyslogFacilitySyslog,
         .severity = kSyslogSeverityNotice},
        {.app      = "app",
         .msgid    = "EVENT",
         .message  = "worker=3 status=ok latency_ms=12",
         .facility = kSyslogFacilityLocal7,
         .severity = kSyslogSeverityInfo},
        {.app      = "app",
         .msgid    = "WARN",
         .message  = "retrying upstream request after transient timeout",
         .facility = kSyslogFacilityLocal7,
         .severity = kSyslogSeverityWarning},
        {.app      = "app",
         .msgid    = "ERROR",
         .message  = "backend returned temporary failure",
         .facility = kSyslogFacilityLocal7,
         .severity = kSyslogSeverityError},
    };

    return &events[fastRand32() % (sizeof(events) / sizeof(events[0]))];
}

static const char *junkdatagramsenderSyslogMonthName(int month)
{
    static const char *months[] = {
        "Jan",
        "Feb",
        "Mar",
        "Apr",
        "May",
        "Jun",
        "Jul",
        "Aug",
        "Sep",
        "Oct",
        "Nov",
        "Dec",
    };

    if (month < 1 || month > 12)
    {
        return "Jan";
    }
    return months[(size_t) month - 1U];
}

static bool junkdatagramsenderSyslogBuildRfc3164(sbuf_t *buf, uint32_t write_limit)
{
    char                                     host[32];
    datetime_t                               now   = datetimeNow();
    const junkdatagramsender_syslog_event_t *event = junkdatagramsenderSyslogRandomEvent();
    uint32_t                                 pri   = (uint32_t) event->facility * 8U + event->severity;
    uint32_t                                 pid   = 100U + (fastRand32() % 65000U);

    int written = stringNPrintf((char *) sbufGetMutablePtr(buf),
                                write_limit,
                                "<%u>%s %2d %02d:%02d:%02d %s %s[%u]: %s",
                                (unsigned int) pri,
                                junkdatagramsenderSyslogMonthName(now.month),
                                now.day,
                                now.hour,
                                now.min,
                                now.sec,
                                junkdatagramsenderSyslogRandomHost(host, sizeof(host)),
                                event->app,
                                (unsigned int) pid,
                                event->message);
    if (! stringFormatFits(written, write_limit))
    {
        return false;
    }

    sbufSetLength(buf, (uint32_t) written);
    return true;
}

static bool junkdatagramsenderSyslogBuildRfc5424(sbuf_t *buf, uint32_t write_limit)
{
    char                                     host[32];
    char                                     structured_data[96];
    datetime_t                               now      = datetimeNow();
    const junkdatagramsender_syslog_event_t *event    = junkdatagramsenderSyslogRandomEvent();
    uint32_t                                 pri      = (uint32_t) event->facility * 8U + event->severity;
    uint32_t                                 pid      = 100U + (fastRand32() % 65000U);
    uint32_t                                 sequence = fastRand32() & 0xFFFFU;

    if (! stringFormatFits(stringNPrintf(structured_data,
                                                           sizeof(structured_data),
                                                           "[meta sequence=\"%u\" worker=\"%u\"]",
                                                           (unsigned int) sequence,
                                                           (unsigned int) (fastRand32() % 64U)),
                                             sizeof(structured_data)))
    {
        return false;
    }

    int written = stringNPrintf((char *) sbufGetMutablePtr(buf),
                                write_limit,
                                "<%u>1 %04d-%02d-%02dT%02d:%02d:%02d.%03dZ %s %s %u %s %s %s",
                                (unsigned int) pri,
                                now.year,
                                now.month,
                                now.day,
                                now.hour,
                                now.min,
                                now.sec,
                                now.ms,
                                junkdatagramsenderSyslogRandomHost(host, sizeof(host)),
                                event->app,
                                (unsigned int) pid,
                                event->msgid,
                                structured_data,
                                event->message);
    if (! stringFormatFits(written, write_limit))
    {
        return false;
    }

    sbufSetLength(buf, (uint32_t) written);
    return true;
}

bool junkdatagramsenderSyslogGenerate(sbuf_t *buf, const junkdatagramsender_module_args_t *args)
{
    uint32_t write_limit = junkdatagramsenderSyslogWriteLimit(buf, args);
    if (write_limit < 32)
    {
        return false;
    }

    sbufSetLength(buf, 0);
    if ((fastRand32() % 100U) < 55U)
    {
        return junkdatagramsenderSyslogBuildRfc5424(buf, write_limit);
    }
    return junkdatagramsenderSyslogBuildRfc3164(buf, write_limit);
}
