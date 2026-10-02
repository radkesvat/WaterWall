# tundevice_gso_live

## Execution and checks

Real default-GSO versus explicitly disabled TUN, including frame limits, kernel wire comparison and TCP/MPTCP/MD5 paths. Namespace/veth/TUN/ioctl setup and independent packet checks stay local; fixed workloads/worker overrides and deadlines are unchanged. Requires Linux root/TUN/iproute2; unavailable prerequisites stay skip77.

Topology: tun: TunDevice → raw; raw: RawSocket.

See [probe.py](probe.py) for the exact staged inputs and observable checks. Run through CTest so namespace/privilege prerequisites and private artifacts are preserved.

CTest: `waterwall.tundevice_gso_live`.
