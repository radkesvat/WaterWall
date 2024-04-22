# see Makefile.vars

set(BASE_HEADERS
    base/hplatform.h
    base/hdef.h
    base/hatomic.h
    base/herr.h
    base/htime.h
    base/hmath.h
    base/hbase.h
    base/hversion.h
    base/hsysinfo.h
    base/hproc.h
    base/hthread.h
    base/hmutex.h
    base/hsocket.h
    base/hlog.h
    base/hbuf.h
    base/hmain.h
    base/hendian.h
)


set(EVENT_HEADERS
    event/hloop.h
    event/nlog.h
)

set(UTIL_HEADERS
    util/base64.h
    util/md5.h
    util/sha1.h
)



set(PROTOCOL_HEADERS
    protocol/icmp.h
    protocol/dns.h
    protocol/ftp.h
    protocol/smtp.h
)


set(MQTT_HEADERS
    mqtt/mqtt_protocol.h
    mqtt/mqtt_client.h
)
