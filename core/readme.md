# Core Settings

`core.json` is the startup configuration file read by the Waterwall executable.
It configures process-wide behavior: which node config files are loaded, where
logs are written, how many workers are created, which runtime memory profile is
used, and how the shared async DNS resolver should behave.

The core file does not define tunnels directly. Tunnel chains are loaded from the
paths listed in `configs`.

## Structural Example

```json
{
  "log": {
    "path": "log/",
    "internal": {
      "loglevel": "INFO",
      "file": "internal.log",
      "console": true
    },
    "core": {
      "loglevel": "INFO",
      "file": "core.log",
      "console": true
    },
    "network": {
      "loglevel": "INFO",
      "file": "network.log",
      "console": true
    },
    "dns": {
      "loglevel": "INFO",
      "file": "dns.log",
      "console": true
    }
  },
  "misc": {
    "workers": 4,
    "ram-profile": "server",
    "mtu": 1500,
    "libs-path": "libs/"
  },
  "dns": {
    "domain-strategy": "prefer-ipv4",
    "timeout-ms": 1000,
    "max-timeout-ms": 5000,
    "tries": 2,
    "query-cache-max-ttl": 1800,
    "ndots": 1,
    "udp-port": 53,
    "tcp-port": 53,
    "socket-send-buffer-size": 262144,
    "socket-receive-buffer-size": 262144,
    "edns-packet-size": 1232,
    "udp-max-queries": 0,
    "flags": ["edns", "dns0x20"],
    "rotate": true,
    "domains": ["example.com"],
    "lookups": "bf",
    "resolvconf-path": "/etc/resolv.conf",
    "hosts-path": "/etc/hosts",
    "sortlist": "10.0.0.0/8",
    "servers": ["1.1.1.1", "8.8.8.8"],
    "server-failover": {
      "retry-chance": 10,
      "retry-delay-ms": 5000
    }
  },
  "configs": [
    "config.json"
  ]
}
```

All top-level sections except `configs` are optional, but production configs
should usually keep `misc` explicit so the worker count, MTU, library path, and
memory profile are intentional.

## Top-Level Options

| Option | Type | Required | Description |
| --- | --- | --- | --- |
| `configs` | array of strings | yes | List of Waterwall node config files to parse and run. |
| `log` | object | no | Logger paths, files, levels, and console output settings. |
| `misc` | object | no | Runtime worker, memory, MTU, and tunnel library settings. |
| `dns` | object | no | Shared async DNS resolver options and default domain strategy. |

`domain-strategy` is not valid as a top-level option. Configure it as
`dns.domain-strategy`.

## `configs`

`configs` must be a non-empty array. Each string is a config file path that the
node manager will parse after the core runtime is initialized.

Example:

```json
{
  "configs": [
    "server.json",
    "reverse.json"
  ]
}
```

The paths are passed to the config loader as written. In normal deployments they
are relative to the process working directory.

## `log`

The `log` object controls the four process loggers:

| Logger | Purpose |
| --- | --- |
| `internal` | Low-level/internal Waterwall logs. |
| `core` | Core startup, config parsing, and runtime manager logs. |
| `network` | Network and tunnel runtime logs. |
| `dns` | Async DNS resolver logs. |

Each logger object accepts:

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `loglevel` | string | `"INFO"` | Minimum log level written by this logger. |
| `file` | string | logger-specific | File name under `log.path`. |
| `console` | boolean | `true` | Whether this logger also writes to console output. |

`log.path` is the base directory used to build log file paths. Waterwall creates
this directory during startup if needed.

Defaults:

| Option | Default |
| --- | --- |
| `log.path` | `"log/"` |
| `log.internal.loglevel` | `"INFO"` |
| `log.internal.file` | `"internal.log"` |
| `log.internal.console` | `true` |
| `log.core.loglevel` | `"INFO"` |
| `log.core.file` | `"core.log"` |
| `log.core.console` | `true` |
| `log.network.loglevel` | `"INFO"` |
| `log.network.file` | `"network.log"` |
| `log.network.console` | `true` |
| `log.dns.loglevel` | `"INFO"` |
| `log.dns.file` | `"dns.log"` |
| `log.dns.console` | `true` |

Accepted log level strings are:

```text
VERBOSE, DEBUG, INFO, WARN, ERROR, FATAL, SILENT
```

The logger uppercases the configured value before applying it.

Example:

```json
{
  "log": {
    "path": "logs/",
    "core": {
      "loglevel": "DEBUG",
      "file": "core.log",
      "console": true
    },
    "network": {
      "loglevel": "INFO",
      "file": "network.log",
      "console": false
    }
  }
}
```

Omitted logger objects use their defaults.

## `misc`

The `misc` object controls process-wide runtime settings.

When `misc` is present and non-empty, omitted fields use the defaults below. If
the whole block is omitted, Waterwall still falls back to CPU core count for
`workers` and `"libs/"` for `libs-path`, but real deployments should keep this
block explicit so `mtu` and `ram-profile` are never accidental.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `workers` | integer | CPU core count | Number of worker threads. Values less than or equal to `0` fall back to CPU core count. Values above `254` are reduced to `254`. |
| `ram-profile` | string or integer | `"server"` | Memory pool sizing profile. |
| `mtu` | integer | `1500` | Global MTU value. Values less than or equal to `0` fall back to `1500`. |
| `libs-path` | string | `"libs/"` | Directory used when loading external tunnel libraries. |

Recommended example:

```json
{
  "misc": {
    "workers": 4,
    "ram-profile": "server",
    "mtu": 1500,
    "libs-path": "libs/"
  }
}
```

### `ram-profile`

String values:

| Value | Meaning |
| --- | --- |
| `"server"` | Larger server-side pool profile. |
| `"client"` | Generic client-side profile. |
| `"client-larger"` | Larger client-side profile. |
| `"minimal"` | Minimal memory profile. |
| `"ultralow"` | Alias of `"minimal"`. |

Integer values are also accepted:

| Value | Profile |
| --- | --- |
| `0` or `1` | S1 memory profile |
| `2` | S2 memory profile |
| `3` | M1 memory profile |
| `4` | M2 memory profile |
| `5` | L1 memory profile |
| `6` | L2 memory profile |

## `dns`

The `dns` object configures the shared c-ares based async resolver used by
workers, plus Waterwall's default domain address selection strategy for connector
nodes.

If `dns` is omitted or empty, the resolver uses Waterwall's c-ares defaults and
`dns.domain-strategy` defaults to `"prefer-ipv4"`.

### `dns.domain-strategy`

`domain-strategy` controls how connector nodes choose an address when a domain
resolves to IPv4 and/or IPv6 records.

This value is the core default for nodes that do not specify their own
`domain-strategy`. `TcpConnector` and `UdpConnector` can still override it in
their own `settings`. `TcpConnector` per-address entries can also override the
connector's default for that specific destination.

Valid string values:

| Value | Behavior |
| --- | --- |
| `"prefer-ipv4"` | Choose the first IPv4 address if one is returned; otherwise fall back to the first IPv6 address. This is the core default. |
| `"prefer-ipv6"` | Choose the first IPv6 address if one is returned; otherwise fall back to the first IPv4 address. |
| `"only-ipv4"` | Use only IPv4 results. If no IPv4 address is returned, resolution is treated as unusable for that connection. |
| `"only-ipv6"` | Use only IPv6 results. If no IPv6 address is returned, resolution is treated as unusable for that connection. |
| `"accept-dns-returned-order"` | Accept the first usable address in the order returned by DNS. |

Legacy integer values are also accepted:

| Value | Strategy |
| --- | --- |
| `0` | `accept-dns-returned-order` |
| `1` | `prefer-ipv4` |
| `2` | `prefer-ipv6` |
| `3` | `only-ipv4` |
| `4` | `only-ipv6` |

Example:

```json
{
  "dns": {
    "domain-strategy": "prefer-ipv4"
  }
}
```

Do not place `domain-strategy` directly in the root object:

```json
{
  "domain-strategy": "prefer-ipv4"
}
```

That form is rejected. Use `dns.domain-strategy`.

### Resolver Timing and Cache Options

| Option | Type | Default | Validation | Description |
| --- | --- | --- | --- | --- |
| `timeout-ms` | integer | `1000` | greater than `0` | Initial DNS query timeout in milliseconds. |
| `max-timeout-ms` | integer | `5000` | greater than `0` | Maximum DNS query timeout in milliseconds. |
| `tries` | integer | `2` | greater than `0` | Number of DNS query tries. |
| `query-cache-max-ttl` | integer | `1800` | greater than or equal to `0` | Maximum TTL, in seconds, for the resolver query cache. |

Example:

```json
{
  "dns": {
    "timeout-ms": 750,
    "max-timeout-ms": 3000,
    "tries": 2,
    "query-cache-max-ttl": 600
  }
}
```

### Resolver Behavior Options

| Option | Type | Validation | Description |
| --- | --- | --- | --- |
| `ndots` | integer | range `0` to `15` | Number of dots required before c-ares tries a name as absolute. |
| `udp-port` | integer | range `1` to `65535` | UDP DNS server port. |
| `tcp-port` | integer | range `1` to `65535` | TCP DNS server port. |
| `socket-send-buffer-size` | integer | greater than `0` | DNS socket send buffer size. |
| `socket-receive-buffer-size` | integer | greater than `0` | DNS socket receive buffer size. |
| `edns-packet-size` | integer | range `1` to `65535` | EDNS packet size. |
| `udp-max-queries` | integer | greater than or equal to `0` | Maximum number of UDP queries allowed by c-ares. |
| `rotate` | boolean | boolean | Enables or disables c-ares server rotation. |

### Search and Source Options

| Option | Type | Validation | Description |
| --- | --- | --- | --- |
| `domains` | array of strings | non-empty array, non-empty strings | Search domains passed to c-ares. |
| `lookups` | string | contains only `b` and `f`; no repeated characters | Lookup source order. `b` means DNS, `f` means hosts file. |
| `resolvconf-path` | string | non-empty | Custom resolv.conf path. |
| `hosts-path` | string | non-empty | Custom hosts file path. |
| `sortlist` | string | non-empty | c-ares sortlist string. |
| `servers` | string or array of strings | non-empty; array items may not contain commas | DNS servers passed to c-ares. A string may use c-ares CSV syntax; an array is joined as CSV. |

Example:

```json
{
  "dns": {
    "servers": ["1.1.1.1", "8.8.8.8"],
    "lookups": "bf",
    "domains": ["example.com"],
    "hosts-path": "/etc/hosts"
  }
}
```

`lookups` examples:

| Value | Meaning |
| --- | --- |
| `"b"` | DNS only. |
| `"f"` | Hosts file only. |
| `"bf"` | Try DNS, then hosts file. |
| `"fb"` | Try hosts file, then DNS. |

### `dns.flags`

`flags` configures supported c-ares flags. It can be written as:

1. A numeric bitmask.
2. A single flag name.
3. An array of flag names.
4. An object whose keys are flag names and whose values are booleans.

Examples:

```json
{
  "dns": {
    "flags": ["edns", "dns0x20"]
  }
}
```

```json
{
  "dns": {
    "flags": {
      "edns": true,
      "dns0x20": true,
      "use-vc": false
    }
  }
}
```

Supported flag names:

| Name | c-ares flag |
| --- | --- |
| `"usevc"` | `ARES_FLAG_USEVC` |
| `"use-vc"` | `ARES_FLAG_USEVC` |
| `"tcp"` | `ARES_FLAG_USEVC` |
| `"primary"` | `ARES_FLAG_PRIMARY` |
| `"igntc"` | `ARES_FLAG_IGNTC` |
| `"ignore-truncated"` | `ARES_FLAG_IGNTC` |
| `"norecurse"` | `ARES_FLAG_NORECURSE` |
| `"no-recurse"` | `ARES_FLAG_NORECURSE` |
| `"stayopen"` | `ARES_FLAG_STAYOPEN` |
| `"stay-open"` | `ARES_FLAG_STAYOPEN` |
| `"no-search"` | `ARES_FLAG_NOSEARCH` |
| `"no-aliases"` | `ARES_FLAG_NOALIASES` |
| `"nocheckresp"` | `ARES_FLAG_NOCHECKRESP` |
| `"no-check-response"` | `ARES_FLAG_NOCHECKRESP` |
| `"edns"` | `ARES_FLAG_EDNS` |
| `"no-default-server"` | `ARES_FLAG_NO_DFLT_SVR` |
| `"no-dflt-svr"` | `ARES_FLAG_NO_DFLT_SVR` |
| `"dns0x20"` | `ARES_FLAG_DNS0x20` |

When object syntax is used, `true` enables a flag and `false` leaves it disabled.

### `dns.server-failover`

`server-failover` is an object passed to c-ares server failover options.

| Option | Type | Default | Validation | Description |
| --- | --- | --- | --- | --- |
| `retry-chance` | integer | `10` | range `0` to `65535` | c-ares retry chance value. |
| `retry-delay-ms` | integer | `5000` | greater than or equal to `0` | Delay before retrying a failed DNS server. |

Example:

```json
{
  "dns": {
    "server-failover": {
      "retry-chance": 25,
      "retry-delay-ms": 2000
    }
  }
}
```

## Minimal Practical `core.json`

```json
{
  "log": {
    "path": "log/",
    "core": {
      "loglevel": "INFO",
      "file": "core.log",
      "console": true
    },
    "network": {
      "loglevel": "INFO",
      "file": "network.log",
      "console": true
    },
    "dns": {
      "loglevel": "INFO",
      "file": "dns.log",
      "console": true
    },
    "internal": {
      "loglevel": "INFO",
      "file": "internal.log",
      "console": true
    }
  },
  "misc": {
    "workers": 4,
    "ram-profile": "server",
    "mtu": 1500,
    "libs-path": "libs/"
  },
  "dns": {
    "domain-strategy": "prefer-ipv4"
  },
  "configs": [
    "config.json"
  ]
}
```

## DNS-Tuned `core.json`

```json
{
  "log": {
    "path": "log/",
    "core": {
      "loglevel": "INFO",
      "file": "core.log",
      "console": true
    },
    "network": {
      "loglevel": "WARN",
      "file": "network.log",
      "console": false
    },
    "dns": {
      "loglevel": "DEBUG",
      "file": "dns.log",
      "console": true
    },
    "internal": {
      "loglevel": "INFO",
      "file": "internal.log",
      "console": false
    }
  },
  "misc": {
    "workers": 8,
    "ram-profile": "client-larger",
    "mtu": 1500,
    "libs-path": "libs/"
  },
  "dns": {
    "domain-strategy": "prefer-ipv4",
    "servers": [
      "1.1.1.1",
      "8.8.8.8"
    ],
    "timeout-ms": 1000,
    "max-timeout-ms": 5000,
    "tries": 2,
    "query-cache-max-ttl": 600,
    "lookups": "bf",
    "flags": [
      "edns",
      "dns0x20"
    ],
    "rotate": true,
    "server-failover": {
      "retry-chance": 10,
      "retry-delay-ms": 5000
    }
  },
  "configs": [
    "server.json",
    "reverse.json"
  ]
}
```
