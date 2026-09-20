"""
Packet Sniffer
Captures live packets on the default network interface using Scapy.

REQUIRES:
- Administrator/root privileges (raw socket access).
- On Windows: Npcap installed (https://npcap.com), with "WinPcap API-compatible
  mode" checked during install.

IMPORTANT: Only capture traffic on networks/interfaces you own or have
explicit permission to monitor.
"""

from scapy.all import sniff, IP, TCP, UDP, ICMP
from scapy.error import Scapy_Exception


def _protocol_name(pkt) -> str:
    if pkt.haslayer(TCP):
        return "TCP"
    if pkt.haslayer(UDP):
        return "UDP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    return "OTHER"


def capture_packets(count: int = 20, timeout: int = 15) -> dict:
    """
    Capture up to `count` packets or stop after `timeout` seconds, whichever
    comes first. Returns a dict with a list of packet summaries plus any
    error encountered (e.g. missing permissions).
    """
    captured = []

    def handle_packet(pkt):
        if pkt.haslayer(IP):
            captured.append({
                "src": pkt[IP].src,
                "dst": pkt[IP].dst,
                "protocol": _protocol_name(pkt),
                "size": len(pkt),
            })

    try:
        sniff(prn=handle_packet, count=count, timeout=timeout, store=False)
        return {"packets": captured, "error": None}
    except PermissionError:
        return {
            "packets": [],
            "error": "Permission denied. Packet capture requires administrator/root privileges.",
        }
    except Scapy_Exception as e:
        return {
            "packets": [],
            "error": f"Capture failed: {e}. On Windows, make sure Npcap is installed.",
        }
    except OSError as e:
        return {
            "packets": [],
            "error": f"Capture failed: {e}. Make sure Npcap/WinPcap is installed and you're running as administrator.",
        }
