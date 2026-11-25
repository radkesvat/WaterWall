#pragma once

#include <stdbool.h>
#include <stddef.h>

typedef struct asyncdns_options_s
{
    bool defaults_initialized;

    unsigned int query_cache_max_ttl;
    int          timeout_ms;
    int          max_timeout_ms;
    int          tries;

    bool flags_set;
    int  flags;

    bool ndots_set;
    int  ndots;

    bool           udp_port_set;
    unsigned short udp_port;

    bool           tcp_port_set;
    unsigned short tcp_port;

    bool socket_send_buffer_size_set;
    int  socket_send_buffer_size;

    bool socket_receive_buffer_size_set;
    int  socket_receive_buffer_size;

    bool ednspsz_set;
    int  ednspsz;

    bool udp_max_queries_set;
    int  udp_max_queries;

    char **domains;
    int    ndomains;

    char *lookups;
    char *resolvconf_path;
    char *hosts_path;
    char *servers_csv;
    char *sortlist;

    bool rotate_set;
    bool rotate;

    bool           server_failover_set;
    unsigned short server_failover_retry_chance;
    size_t         server_failover_retry_delay_ms;
} asyncdns_options_t;
