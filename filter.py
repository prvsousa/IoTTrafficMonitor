
from scapy.all import *
from netfilterqueue import NetfilterQueue
from subprocess import Popen, PIPE
import socket
import argparse

###NOTE THAT YOU SHOULD SETUP THE HOTSPOT WITH 
#Add these three iptable firewall rules to get the traffic"
os.system("sudo iptables -F")
os.system("sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
os.system("sudo iptables -A INPUT -i eth0 -p tcp --dport 22 -j ACCEPT")
os.system("sudo iptables -A INPUT -i wlan0 -j NFQUEUE --queue-num 1")
os.system("sudo iptables -A FORWARD -i wlan0 -j NFQUEUE --queue-num 1")

parser = argparse.ArgumentParser(description='MiTM tool', usage='./filter -o <capture_file>')
parser.add_argument('-o', '--output', type=str, help='Capture file name', default='capture.pcap')

args = parser.parse_args()
filename = args.output
packets = PacketList()

if not args.output.endswith('.pcap'):
    filename += '.pcap'

IP_DATE = {}
IP_PORTS = {}
IP_DST_IPS = {}

#Given an IP address, the function returns the organization of this IP
def getOrg(ip):
    try:
        whois_origin  = 'whois -h whois.radb.net -- -i origin %s | grep descr: | awk \'{print $2}\'' % (ip)
        whois_data = subprocess.check_output(whois_origin, shell=True).decode('utf-8')
        return whois_data
    except subprocess.CalledProcessError as grepexc:
        return "error code" + grepexc.returncode + grepexc.output
    except subprocess.CalledProcessError as e:
        print(e.output)    

#Given an IP address, the function returns a tuple containing the Host Name, Alias list for the IP address if any and IP address of the host
def getHostByAddr(ip):
    try:
        return socket.gethostbyaddr(ip)
    except socket.herror:
        return "Not returning Hostname... Getting IP Address" + ip


#Defines if the packet is accepted or dropped according to the returning functions
def filter(packet):
    if ipPortFilter(packet) and ipFilter(packet):
        packet.accept()
        save_packet(packet)
    else:
        packet.drop()

    
def ipPortFilter(packet):
    pkt = IP(packet.get_payload())
    pkt_ip = pkt.src
    if pkt_ip not in IP_DATE:
        print("> New device at ip: " + str(pkt_ip))
        IP_DATE[pkt_ip] = datetime.now()
        IP_PORTS[pkt_ip] = []
        IP_DST_IPS[pkt_ip] = []
        
    if TCP in pkt:
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        dst_port = pkt[UDP].dport
    else: # For now accept unknown protocols
        return True

    ports = IP_PORTS[pkt_ip]
    # Check if the device has already been tracked for a day
    if (datetime.now() - IP_DATE[pkt_ip]).days > 0:
        # Check if the port is valid, if not then drop the
        # packet
        if dst_port in ports:
            return True
        else:
            print(">>> Packet dropped from " + str(pkt_ip) + " on unvalidated port: " + str(dst_port))
            return False
    else:
        # Device is new so track the ports that it uses
        if dst_port not in ports:
            print(">> New port on ip: " + str(pkt_ip) + " port: " + str(dst_port))
            ports.append(dst_port)
        return True

def ipFilter(packet):
    pkt = IP(packet.get_payload())
    pkt_src_ip = pkt.src
    pkt_dst_ip = pkt.dst

    if pkt_src_ip not in IP_DATE:
        print("> New device at ip: " + str(pkt_src_ip))
        IP_DATE[pkt_src_ip] = datetime.now()
        IP_PORTS[pkt_src_ip] = []
        IP_DST_IPS[pkt_src_ip] = []

    ips = IP_DST_IPS[pkt_src_ip]
    if (datetime.now() - IP_DATE[pkt_src_ip]).days > 0:
        if pkt_dst_ip in ips:
            return True
        else:
            print(">>> Packet dropped from " + str(pkt_src_ip) + " to unvalidated destination: " + str(pkt_dst_ip))
            return False
    else:
        if pkt_dst_ip not in ips:
            print(">> New destination ip for ip: " + str(pkt_src_ip) + " ip: " + str(pkt_dst_ip))
           
            #Drop packets of all organizations except a defined organization
            org = getOrg(pkt_dst_ip)
            print(org)
            if org is not None and ('Google' not in org and org != ('')):
                print("Packet dropped " + org)
                return False

            ips.append(pkt_dst_ip)

            print(getHostByAddr(pkt_dst_ip))

        return True     

    
    
def save_packet(packet):
    pkt = IP(packet.get_payload())
    global packets
    packets.append(pkt)
    wrpcap(filename, packets)

    
try:
    nfqueue = NetfilterQueue()
    nfqueue.bind(1, filter)
except Exception as e:
    print(str(e))

    
try:
    print("[*] waiting for data")
    nfqueue.run()
except Exception as e:
    print(str(e))
except KeyboardInterrupt:
    pass                
