"""
Port Scanner
Tries python-nmap first (requires the nmap binary installed and on PATH).
Falls back to a pure-Python threaded socket scan if nmap isn't available,
so the feature still works on machines without Nmap installed.

IMPORTANT: Only scan hosts/IPs you own or have explicit permission to test.
"""

import socket
import concurrent.futures

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False

# Common ports to check in the socket fallback (keeps scan time reasonable)
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8080, 8443]


def _service_name(port: int) -> str:
    try:
        name = socket.getservbyport(port)
        return name.split()[0].strip() if name else "unknown"
    except OSError:
        return "unknown"


def _scan_with_nmap(target: str, ports: str) -> dict:
    scanner = nmap.PortScanner()
    scanner.scan(target, ports, arguments="-T4")

    results = []
    if target in scanner.all_hosts():
        for proto in scanner[target].all_protocols():
            for port in sorted(scanner[target][proto].keys()):
                info = scanner[target][proto][port]
                results.append({
                    "port": port,
                    "status": info["state"],  # 'open', 'closed', 'filtered'
                    "service": info.get("name", "unknown"),
                })
    return {"engine": "nmap", "target": target, "results": results}


def _scan_with_sockets(target: str, port_list) -> dict:
    def check_port(port):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((target, port))
            status = "open" if result == 0 else "closed"
        except socket.error:
            status = "closed"
        finally:
            sock.close()
        return {"port": port, "status": status, "service": _service_name(port)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:
        results = list(executor.map(check_port, port_list))

    results.sort(key=lambda r: r["port"])
    return {"engine": "socket (fallback)", "target": target, "results": results}


def scan_target(target: str, port_range: str = "1-1024") -> dict:
    """
    port_range: nmap-style string like '1-1024' or '22,80,443'.
    Returns dict with engine used, target, and list of {port, status, service}.
    """
    try:
        socket.gethostbyname(target)  # validate resolvable host/IP
    except socket.gaierror:
        return {"engine": None, "target": target, "results": [], "error": "Could not resolve host."}

    if NMAP_AVAILABLE:
        try:
            return _scan_with_nmap(target, port_range)
        except Exception:
            # nmap library present but binary missing/broken -> fall back
            pass

    # Build a port list for the fallback scanner
    if "-" in port_range:
        start, end = port_range.split("-")
        start, end = int(start), int(end)
        # Cap the range for the slower fallback scanner to keep it responsive
        port_list = list(range(start, min(end, start + 200) + 1))
    else:
        port_list = [int(p) for p in port_range.split(",") if p.strip().isdigit()]
        if not port_list:
            port_list = COMMON_PORTS

    return _scan_with_sockets(target, port_list)
