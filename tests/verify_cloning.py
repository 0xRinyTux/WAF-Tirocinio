
import socket
import sys
import struct

def start_sniffer(interface="eth0"):
    print(f"[*] Sniffing on {interface} for cloned packets...")
    
    try:
        # AF_PACKET to see everything at Ethernet level
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        sock.bind((interface, 0))
        
        while True:
            data, addr = sock.recvfrom(65535)
            # Parse IP header
            eth_len = 14
            ip_header = data[eth_len:20+eth_len]
            # Verify IP version
            version_ihl = ip_header[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            iph_length = ihl * 4

            iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
            protocol = iph[6]
            s_addr = socket.inet_ntoa(iph[8])
            d_addr = socket.inet_ntoa(iph[9])

            if protocol == 6: # TCP
                # if d_addr == "192.168.16.3":
                     print(f"[!] CLONED PACKET RECEIVED: {s_addr} -> {d_addr}")
                     try:
                        print(f"    Payload sample: {data[54:100]}")
                     except:
                        pass
                    
    except PermissionError:
        print("[!] Need root to sniff!")
    except Exception as e:
        print(f"[!] Sniffer error: {e}")

if __name__ == "__main__":
    print("--- Traffic Simulation Sniffer ---")
    start_sniffer()
