"""Bounded namespace-local command mechanics; policy/rules stay in the test."""
import subprocess


def command(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT, timeout=10)


def iptables(*args):
    return command("iptables", "-w", "5", *args)
