#!/bin/bash
IPT="/sbin/iptables"

# Server IP
SERVER_IP="$(ip addr show br0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"
DOCKER_OVERLAY_IP="$(ip addr show docker_gwbridge | grep 'inet ' | cut -f2 | awk '{ print $2}')"
DOCKER_BRIDGE_IP="$(ip addr show docker0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"
VIRT_BRIDGE_IP="$(ip addr show virbr0 | grep 'inet ' | cut -f2 | awk '{ print $2}')"

# Your DNS servers you use: cat /etc/resolv.conf
DNS_SERVER="8.8.4.4 8.8.8.8"

# Allow connections to this package servers
#PACKAGE_SERVER="archive.ubuntu.com security.ubuntu.com"

echo "flush iptable rules"
$IPT -F
$IPT -X
$IPT -t nat -F
$IPT -t nat -X
$IPT -t mangle -F
$IPT -t mangle -X

echo "Set default policy to 'DROP'"
$IPT -P INPUT   DROP
$IPT -P FORWARD DROP
$IPT -P OUTPUT  DROP

## Antispoofing
$IPT -A INPUT --in-interface !lo --source 127.0.0.0/8 -j DROP
## Smurf attach -- limits the ping request
$IPT -A INPUT -p icmp -m icmp --icmp-type 8 -m limit --limit 1/second -j ACCEPT
#drop bogus packets

$IPT -A INPUT   -m state --state INVALID -j DROP
$IPT -A FORWARD -m state --state INVALID -j DROP
$IPT -A OUTPUT  -m state --state INVALID -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags FIN,ACK FIN -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPT -t filter -A INPUT -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP

## This should be one of the first rules.
## so dns lookups are already allowed for your other rules
for ip in $DNS_SERVER
do
	echo "Allowing DNS lookups (tcp, udp port 53) to server '$ip'"
	$IPT -A OUTPUT -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p udp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
	$IPT -A OUTPUT -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s $ip --sport 53 -m state --state ESTABLISHED     -j ACCEPT
done

echo "allow all and everything on localhost"
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT

for ip in $PACKAGE_SERVER
do
	echo "Allow connection to '$ip' on port 21"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 21  -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 21  -m state --state ESTABLISHED     -j ACCEPT

	echo "Allow connection to '$ip' on port 80"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 80  -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 80  -m state --state ESTABLISHED     -j ACCEPT

	echo "Allow connection to '$ip' on port 443"
	$IPT -A OUTPUT -p tcp -d "$ip" --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT
	$IPT -A INPUT  -p tcp -s "$ip" --sport 443 -m state --state ESTABLISHED     -j ACCEPT
done


#######################################################################################################
## Global iptable rules. Not IP specific

#echo "Allowing new and established incoming connections to port 21, 80, 443"
#$IPT -A INPUT  -p tcp -m multiport --dports 21,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
#$IPT -A OUTPUT -p tcp -m multiport --sports 21,80,443 -m state --state ESTABLISHED     -j ACCEPT

## Global allow all connections initiated from local machine to outside world via bridge
$IPT -A INPUT -i br0 -s 192.168.0.0/24 -j ACCEPT
$IPT -A INPUT -i docker_gwbridge -s $DOCKER_OVERLAY_IP -j ACCEPT
$IPT -A INPUT -i docker0 -s $DOCKER_BRIDGE_IP -j ACCEPT
$IPT -A INPUT -i virbr0 -s $VIRT_BRIDGE_IP -j ACCEPT
$IPT -A OUTPUT -o virbr0 -s $VIRT_BRIDGE_IP -j ACCEPT
$IPT -A OUTPUT -o docker0 -s $DOCKER_BRIDGE_IP -j ACCEPT
$IPT -A OUTPUT -o docker_gwbridge -s $DOCKER_OVERLAY_IP -j ACCEPT
$IPT -t nat -I POSTROUTING -o docker_gwbridge -j MASQUERADE

$IPT -A INPUT -i br0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i docker_gwbridge -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i docker0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT -i virbr0 -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPT -A FORWARD -i br0 -j ACCEPT
$IPT -A OUTPUT -p tcp -s $SERVER_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p udp -s $SERVER_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -s $DOCKER_BRIDGE_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p udp -s $DOCKER_BRIDGE_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -s $DOCKER_OVERLAY_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p udp -s $DOCKER_OVERLAY_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p tcp -s $VIRT_BRIDGE_IP -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -p udp -s $VIRT_BRIDGE_IP -m state --state NEW,ESTABLISHED -j ACCEPT


echo "Allow all outgoing connections to port 22"
$IPT -A OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -p tcp --sport 22 -m state --state ESTABLISHED     -j ACCEPT

echo "Allow all incoming connections to port 22"
$IPT -A INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT  -p tcp --sport 22 -m state --state ESTABLISHED     -j ACCEPT

echo "Allow all incoming connections to port 5900 for VNC"
$IPT -A INPUT -p tcp --dport 5900 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --dport 5800 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT -p tcp --dport 6000 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A OUTPUT  -p tcp --sport 6000 -m state --state ESTABLISHED     -j ACCEPT
$IPT -A OUTPUT  -p tcp --sport 5900 -m state --state ESTABLISHED     -j ACCEPT
$IPT -A OUTPUT  -p tcp --sport 5800 -m state --state ESTABLISHED     -j ACCEPT

echo "Allow cowsay service on virbr0"
#source ./iptable-rules-to-expose-service.sh
#iptables -t nat -A PREROUTING -p tcp -i br0 --dport 32737 -j DNAT --to-destination 192.168.39.142:32737
#iptables -A FORWARD -i br0 -o virbr0 -p tcp --dport 32737 -j ACCEPT
#iptables -A FORWARD -i virbr0 -o br0 -j ACCEPT
#iptables -t nat -I POSTROUTING -o virbr0 -j MASQUERADE
echo "Allow cowsay service on virbr0"
runuser -l sunils -c "minikube service cowsay-ui -n web --url | sed 's/http:\/\///' | sed 's/:[0-9]*//'"
endpoint=$(runuser -l sunils -c "minikube service cowsay-ui -n web --url | sed 's/http:\/\///' | sed 's/:[0-9]*//'")
port=$(runuser -l sunils -c "minikube service cowsay-ui -n web --url | sed 's/http:\/\///' | sed 's/[0-9]\+\.[0-9]\+\.[0-9]\+\.[0-9]\+\://'")
#echo $endpoint | xargs iptables -t nat -A PREROUTING -p tcp -i br0 --dport 32737 -j DNAT --to-destination $1
iptables -t nat -A PREROUTING -p tcp -i br0 --dport 32737 -j DNAT --to-destination $endpoint
iptables -A FORWARD -i br0 -o virbr0 -p tcp --dport 32737 -j ACCEPT
iptables -A FORWARD -i virbr0 -o br0 -j ACCEPT
iptables -t nat -I POSTROUTING -o virbr0 -j MASQUERADE


echo "Allow kube dashboard service on loopback"
iptables -t nat -A PREROUTING -p tcp -i br0 --dport 30000 -j DNAT --to-destination 192.168.39.12:30000
iptables -A FORWARD -i br0 -o virbr0 -p tcp --dport 30000 -j ACCEPT
iptables -A FORWARD -i virbr0 -o br0 -j ACCEPT
iptables -t nat -I POSTROUTING -o virbr0 -j MASQUERADE

echo "allow samba connections"
iptables -A INPUT -p udp -m udp --dport 137 -j ACCEPT
iptables -A INPUT -p udp -m udp --dport 138 -j ACCEPT
iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport 139 -j ACCEPT
iptables -A INPUT -m state --state NEW -m tcp -p tcp --dport 445 -j ACCEPT

echo "Allow outgoing icmp connections (pings,...)"
$IPT -A OUTPUT -p icmp -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPT -A INPUT  -p icmp -m state --state ESTABLISHED,RELATED     -j ACCEPT

echo "Allow outgoing connections to port 123 (ntp syncs)"
$IPT -A OUTPUT -p udp --dport 123 -m state --state NEW,ESTABLISHED -j ACCEPT
$IPT -A INPUT  -p udp --sport 123 -m state --state ESTABLISHED     -j ACCEPT

# Log before dropping
$IPT -A INPUT  -j LOG  -m limit --limit 12/min --log-level 4 --log-prefix 'IP INPUT drop: '
$IPT -A INPUT  -j DROP

$IPT -A OUTPUT -j LOG  -m limit --limit 12/min --log-level 4 --log-prefix 'IP OUTPUT drop: '
$IPT -A OUTPUT -j DROP

exit 0
