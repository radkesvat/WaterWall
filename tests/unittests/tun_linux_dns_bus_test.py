#!/usr/bin/env python3
"""Exercise real supervised busctl against an isolated, in-memory resolver service."""
import argparse
import os
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--build-dir")
    parser.add_argument("--config")
    parser.add_argument("executable")
    args = parser.parse_args()
    try:
        import dbus
        import dbus.service
        from dbus.mainloop.glib import DBusGMainLoop
        from gi.repository import GLib
    except ImportError:
        print("SKIP: private DNS bus fixture requires Python dbus and GLib")
        return 77
    if not all(shutil.which(tool) for tool in ("busctl", "dbus-run-session")):
        print("SKIP: private DNS bus fixture requires busctl and dbus-run-session")
        return 77
    if not args.inside:
        subprocess.run(["cmake", "--build", args.build_dir, "--config", args.config,
                        "--target", "tun_linux_dns_test"], check=True)
        return subprocess.call(["dbus-run-session", "--", sys.executable, __file__, "--inside", args.executable])

    DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    name = dbus.service.BusName("org.freedesktop.resolve1", bus)
    link_path = "/org/freedesktop/resolve1/link/_342"
    link_interface = "org.freedesktop.resolve1.Link"

    class Manager(dbus.service.Object):
        @dbus.service.method("org.freedesktop.resolve1.Manager", in_signature="i", out_signature="o")
        def GetLink(self, index):
            assert index == 42
            return dbus.ObjectPath(link_path)

    class Link(dbus.service.Object):
        @dbus.service.method("org.freedesktop.DBus.Properties", in_signature="ss", out_signature="v")
        def Get(self, interface, prop):
            assert interface == link_interface and prop in ("DNSEx", "Domains")
            return self.values[prop]

        @dbus.service.method(link_interface, in_signature="a(iayqs)", out_signature="")
        def SetDNSEx(self, values):
            self.writes += 1
            self.values["DNSEx"] = values

        @dbus.service.method(link_interface, in_signature="a(sb)", out_signature="")
        def SetDomains(self, values):
            self.writes += 1
            self.values["Domains"] = values

    manager = Manager(name, "/org/freedesktop/resolve1")
    link = Link(name, link_path)
    env = dict(os.environ, DBUS_SYSTEM_BUS_ADDRESS=os.environ["DBUS_SESSION_BUS_ADDRESS"],
               WW_TUN_DNS_TEST_PRIVATE_BUS="1")
    for empty in (False, True):
        servers = [] if empty else [
            (dbus.Int32(2), dbus.ByteArray(bytes([10, 0, 0, 53])), dbus.UInt16(5353), dbus.String("dns.corp")),
            (dbus.Int32(10), dbus.ByteArray(bytes.fromhex("20010db8000000000000000000000035")),
             dbus.UInt16(853), dbus.String("v6.corp"))]
        domains = [] if empty else [("z.corp", False), ("a.corp", False), ("vpn.corp", True)]
        baseline = {"DNSEx": dbus.Array(servers, signature="(iayqs)"),
                    "Domains": dbus.Array(domains, signature="(sb)")}
        link.values = dict(baseline)
        link.writes = 0
        loop = GLib.MainLoop()
        child = subprocess.Popen([args.executable], env=env)

        def poll():
            if child.poll() is None:
                return True
            loop.quit()
            return False

        def timeout():
            child.kill()
            loop.quit()
            return False

        poll_id = GLib.timeout_add(25, poll)
        timeout_id = GLib.timeout_add_seconds(30, timeout)
        try:
            loop.run()
            assert child.wait(timeout=5) == 0, "real command fixture failed"
            assert link.writes == 4, "expected two setup and two scoped restoration operations"
            def dns_values(values):
                return [(int(family), bytes(address), int(port), str(server))
                        for family, address, port, server in values]

            assert dns_values(link.values["DNSEx"]) == dns_values(baseline["DNSEx"]), "DNS baseline changed"
            assert list(link.values["Domains"]) == list(baseline["Domains"]), "domain values/order changed"
        finally:
            if child.poll() is None:
                child.kill()
                child.wait()
            if GLib.MainContext.default().find_source_by_id(timeout_id):
                GLib.source_remove(timeout_id)
            if GLib.MainContext.default().find_source_by_id(poll_id):
                GLib.source_remove(poll_id)
    print("Private-bus DNS setup/restoration passed with real busctl and process supervisor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
