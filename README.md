run with a vpn server. this script will receive rooms and send the room list to player.
I suggest that use the vpn call WireGuard. It is easy and fast.

need to use python3.8+, and install tshark.

before run it. need to modify something.

intface = "interface_name"   # your vpn interface name
tshark_path = "/usr/bin/tshark"   # your tshark path
# a.b.c.d, here use 10.5.0.0/16
ipv4_a = 10
ipv4_b = 5
