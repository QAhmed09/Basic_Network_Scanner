import argparse
import concurrent.futures
import socket
import ssl
import sys
import re
from datetime import datetime


def parse_ports(port_arg):
    """Parse port argument supporting 'common', single ports, comma lists and ranges like 1-1024."""
    if port_arg == "common":
        return list(range(1, 1025)), "1-1024"

    ports = set()
    for part in port_arg.split(','):
        part = part.strip()
        if '-' in part:
            try:
                start, end = part.split('-', 1)
                start = int(start); end = int(end)
                ports.update(range(start, end + 1))
            except ValueError:
                raise ValueError(f"Invalid port range: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                raise ValueError(f"Invalid port: {part}")

    port_list = sorted(p for p in ports if 1 <= p <= 65535)
    return port_list, port_arg


def grab_banner(s, port):
    """Attempt to read a banner; if nothing received and port looks like HTTP, send a HEAD request."""
    try:
        s.settimeout(1.0)
        try:
            data = s.recv(1024)
        except socket.timeout:
            data = b''

        # If nothing and HTTP-like port, send HEAD
        if not data and port in (80, 443, 8080):
            try:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                data = s.recv(2048)
            except Exception:
                data = b''

        if data:
            banner = data.decode('utf-8', errors='ignore').strip()
            return banner.split('\n')[0].replace('\r', '')
        return "No banner responded"
    except Exception:
        return "No banner responded"


def scan_port(target_host, port, timeout):
    """Connect to a port (with optional TLS for 443) and return (is_open, banner)."""
    try:
        # create_connection sets up the socket and connects
        s = socket.create_connection((target_host, port), timeout=timeout)
        try:
            if port == 443:
                ctx = ssl.create_default_context()
                # wrap the existing socket for TLS
                s = ctx.wrap_socket(s, server_hostname=target_host)

            banner = grab_banner(s, port)
            return True, banner
        finally:
            try:
                s.close()
            except Exception:
                pass
    except Exception:
        return False, None


def main():
    parser = argparse.ArgumentParser(description="Basic Network Scanner with Service Banner Grabbing")
    parser.add_argument("-t", "--target", help="Target IP address or Hostname to scan", required=True)
    parser.add_argument("-p", "--ports", help="Ports to scan: 'common', a number, comma list or ranges (e.g. 22,80,443 or 1-1024)", default="common")
    parser.add_argument("--timeout", type=float, default=1.5, help="Socket timeout in seconds")
    parser.add_argument("--threads", type=int, default=50, help="Number of threads for concurrent scanning")

    args = parser.parse_args()
    target_host = args.target

    # Resolve hostname to IP address
    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[!] Error: Could not resolve hostname '{target_host}'.")
        sys.exit(1)

    try:
        port_list, port_info = parse_ports(args.ports)
    except ValueError as e:
        print(f"[!] Error: {e}")
        sys.exit(1)

    print("-" * 65)
    print(f"[*] Target Host : {target_host} ({target_ip})")
    print(f"[*] Scanning    : Ports {port_info}")
    print(f"[*] Start Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 65)

    open_ports = 0

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_port = {executor.submit(scan_port, target_ip, port, args.timeout): port for port in port_list}

            for fut in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[fut]
                try:
                    is_open, banner = fut.result()
                except Exception:
                    is_open, banner = False, None

                if is_open:
                    try:
                        default_service = socket.getservbyport(port, 'tcp')
                    except Exception:
                        default_service = "unknown"

                    print(f"[+] Port {port:<5} [OPEN] --> Default Service: {default_service}")
                    print(f"    └── Banner/Version: {banner}")
                    open_ports += 1
                    print("-" * 45)

    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user. Exiting...")
        sys.exit(0)

    print("-" * 65)
    print(f"[*] Scan finished. Found {open_ports} open port(s).")


if __name__ == "__main__":
    main()