# Accelerator
A simple game accelerator

build:
apt-get libpcap-dev
yum install libpcap-devel

# On Windows, must enable Windows firewall for filter
# outbound packets, include RST about TCP(not need rule).
#
# add rule ICMPv4 destination unreachable(type 3, code 3),
# add rule ICMPv6 destination unreachable(type 1, code 4),



#
# On Linux, must use iptables/ip6tables for filter outbound
# packets, include RST about TCP and ICMPv4/ICMPv6.
#
# iptables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
# iptables -A OUTPUT -p icmp -m icmp --icmp-type 3 -j DROP
# ip6tables -A OUTPUT -p tcp -m tcp --tcp-flags RST RST -j DROP
# ip6tables -A OUTPUT -p icmpv6 -m icmpv6 --icmpv6-type 1 -j DROP
#
# recommend enable TCP BBR for better effect(IPv4&IPv6)
# sudo sysctl -w net.ipv4.tcp_congestion_control=bbr
#
