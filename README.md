# IoT Network Traffic Filtering

Turn your Raspberry PI an IoT network monitor by connecting your devices to it.

## 1. Configure Access Point

================== /etc/hostapd/hostapd.conf ============

interface=wlan0
hw_mode=g
channel=7
wmm_enabled=1
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
ssid=RASPi-ApH
wpa_passphrase=GotSecret

==========================================================


================== /etc/default/hostapd ==================

DAEMON_CONF="/etc/hostapd/hostapd.conf"

==========================================================


================== /etc/dhcpcd.conf ======================

#Add this line to the end of file
denyinterfaces wlan0

==========================================================


================== /etc/dnsmasq.conf =====================

interface=wlan0
listen-address=192.168.5.1
bind-interfaces
server=8.8.8.8
domain-needed
bogus-priv
dhcp-range=192.168.5.2,192.168.5.100,24h

=================== RUN THE COMMAND ======================

sudo systemctl unmask hostapd

==========================================================


============== /etc/network/interfaces ===================

auto lo
iface lo inet loopback

auto eth0
iface eth0 inet dhcp

allow-hotplug wlan0
iface wlan0 inet static
address 192.168.5.1
netmask 255.255.255.0
network 192.168.5.0
broadcast 192.168.5.255

==========================================================



========= SET IP TABLES RULES FOR HOTSPOT ================

sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE 
sudo sh -c "iptables-save > /etc/iptables.ipv4.nat"

==========================================================

====================  /etc/rc.local ======================
iptables-restore < /etc/iptables.ipv4.nat


## 2. Run the script

sudo python filter.py
