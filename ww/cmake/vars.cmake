# see Makefile.vars

set(BASE_HEADERS
    base/wplatform.h
    base/wdef.h
    base/watomic.h
    base/werr.h
    base/wtime.h
    base/wmath.h
    base/eventloop_mem.h
    base/wversion.h
    base/wsysinfo.h
    base/wproc.h
    base/wthread.h
    base/wmutex.h
    base/wsocket.h
    base/wlog.h
    base/hbuf.h
    base/hmain.h
    base/wendian.h
)


set(EVENT_HEADERS
    event/hloop.h
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
