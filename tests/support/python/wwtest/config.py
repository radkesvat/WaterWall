"""Generated core settings; callers supply scenario values and write their files."""


STARTED_MARKER = "Core: starting workers ..."


def core_config(*, workers=1, ram_profile="client", console=True, loglevel="DEBUG", **misc):
    """Build the common four-logger config without silently changing node inputs.

    Omitted settings stay omitted; splice/MTU overrides belong to the caller.
    This is used by startup configuration tests and loopback runtime fixtures.
    """
    return {
        "log": {"path": "log/", **{
            name: {"loglevel": loglevel, "file": name + ".log", "console": console}
            for name in ("internal", "core", "network", "dns")}},
        "configs": ["config.json"],
        "misc": {"workers": workers, "ram-profile": ram_profile, "mtu": 1500,
                 "try-enabling-bbr": False, **misc},
    }
