#!/usr/bin/env python3
"""Supervised real busctl against private resolver D-Bus/GLib, nonempty/empty IPv4/IPv6 DNS and ordered
domain restoration. CMake owns the native build/run lock; no nested acquisition. Requires
dbus/GLib/busctl/dbus-run-session; unavailable prerequisites return77. GLib child polling and native
receipts stay explicit. CTest: waterwall.tun_linux_dns_bus_unit."""
import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.dont_write_bytecode = True
sys.path.insert(0, os.environ.get("WATERWALL_TEST_SUPPORT_DIR",
                                str(Path(__file__).resolve().parents[1] / "support" / "python")))
from wwtest.run_directory import RunDirectory
from wwtest.process import kill_and_reap


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--orchestrated", action="store_true")
    parser.add_argument("--build-dir")
    parser.add_argument("--config")
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--source-dir", default=str(Path(__file__).resolve().parents[2]))
    parser.add_argument("--fixture-dir", default=str(Path(__file__).resolve().parent / "fixtures"))
    parser.add_argument("--test-name", default="waterwall.tun_linux_dns_bus_unit")
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
    if not args.inside and not args.orchestrated:
        # CMake owns the same process-scoped lock as ordinary native tests and
        # keeps it through the entire private-bus execution. Stream its output
        # so an outer timeout cannot hide the early artifact announcement.
        control_run = RunDirectory("dns-bus-control-", parent=args.build_dir)
        control = control_run.create()
        control_status = 1
        try:
            result_file = Path(control) / "receipt.txt"
            values = dict(TARGET="tun_linux_dns_test", EXECUTABLE=sys.executable,
                          BUILD_DIR=str(Path(args.build_dir).resolve()), CONFIG=args.config,
                          NAME=args.test_name, SOURCE_DIR=args.source_dir, FIXTURE_DIR=args.fixture_dir,
                          ARGUMENTS=f"{Path(__file__).resolve()};--orchestrated;{Path(args.executable).resolve()}",
                          SKIP_CODE=77, RESULT_FILE=result_file)
            result = subprocess.call([args.cmake, *(f"-DUNIT_TEST_{key}={value}" for key, value in values.items()),
                                      "-P", str(Path(__file__).with_name("run_unit_test.cmake"))])
            control_status = result if result != 0 else int(result_file.read_text().strip())
            return control_status
        finally:
            control_run.finish(control_status)
    if not args.inside:
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
                kill_and_reap(child)
            if GLib.MainContext.default().find_source_by_id(timeout_id):
                GLib.source_remove(timeout_id)
            if GLib.MainContext.default().find_source_by_id(poll_id):
                GLib.source_remove(poll_id)
    print("Private-bus DNS setup/restoration passed with real busctl and process supervisor")
    return 0


if __name__ == "__main__":
    sys.exit(main())
