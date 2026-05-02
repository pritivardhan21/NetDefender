from scapy.all import rdpcap, IP, TCP, UDP, ICMP
import csv

def pcap_to_csv(pcap_file, csv_file, is_attack=0):
    print(f"[*] Reading {pcap_file} (This might take a second)...")
    try:
        packets = rdpcap(pcap_file)
    except FileNotFoundError:
        print(f"[!] Error: Could not find {pcap_file}. Are you in the right directory?")
        return
        
    with open(csv_file, 'w', newline='') as f:
        writer = csv.writer(f)
        # These are the "Features" your AI will analyze
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'protocol', 'packet_length', 'is_attack'])
        
        count = 0
        for pkt in packets:
            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
                pkt_len = len(pkt)
                timestamp = pkt.time
                
                # Identify the protocol
                protocol = 'UNKNOWN'
                if TCP in pkt:
                    protocol = 'TCP'
                elif UDP in pkt:
                    protocol = 'UDP'
                elif ICMP in pkt:
                    protocol = 'ICMP'
                
                # Write to CSV. is_attack=0 because this is our baseline normal traffic
                writer.writerow([timestamp, src_ip, dst_ip, protocol, pkt_len, is_attack])
                count += 1
                
    print(f"[+] Extraction complete! {count} packets parsed and saved to {csv_file}")

# Execute the extraction
pcap_to_csv('normal_traffic.pcap', 'normal_dataset.csv', is_attack=0)
