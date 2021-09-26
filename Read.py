from scapy.all import *

if __name__ == "__main__":
    pcap = rdpcap("stratosphere_capture_0x7.pcap")
    print(pcap) # print the number of packets
    for packet in pcap:
        packet.show()  # print the content of every packet
        ip = packet['IP']
        print("[+] IP.src:", ip.src,";IP.dst:", ip.dst, ";Port.src:", ip.sport, ";Port.dst:", ip.dport, ";Protocol:", ip.proto, ";Length:", ip.len)
