import socket
import threading
from queue import Queue


# -----------------------------
# Resolve domain → IP
# -----------------------------
def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print("[-] Cannot resolve target")
        return None


# -----------------------------
# Service fingerprinting (heuristic)
# -----------------------------
def identify_service(port, banner):
    banner = banner.lower()

    if port == 22:
        return "SSH | Encrypted (key exchange, symmetric crypto)"
    elif port == 80:
        return "HTTP | Unencrypted web protocol"
    elif port == 443:
        return "HTTPS | TLS encrypted web (certificate-based)"
    elif port == 21:
        return "FTP | Usually plaintext (unless FTPS)"
    elif port == 25:
        return "SMTP | Email protocol (may support STARTTLS)"
    elif "ssh" in banner:
        return "SSH (banner detected)"
    elif "http" in banner:
        return "HTTP service detected"
    elif "tls" in banner or "ssl" in banner:
        return "TLS/SSL encrypted service"
    else:
        return "Unknown service"


# -----------------------------
# Try grab service banner
# -----------------------------
def grab_banner(sock):
    try:
        sock.send(b"\r\n")
        return sock.recv(2048).decode(errors="ignore").strip()
    except:
        return ""


# -----------------------------
# Scan logic
# -----------------------------
def scan_port(ip, port, show_closed):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(0.3)

    try:
        result = sock.connect_ex((ip, port))

        if result == 0:
            banner = grab_banner(sock)
            service = identify_service(port, banner)

            print(f"[OPEN] {port} | {service}")

            if banner:
                print(f"        └─ Banner: {banner.splitlines()[0]}")

        elif show_closed:
            print(f"[CLOSED] {port}")

    finally:
        sock.close()


# -----------------------------
# Thread worker
# -----------------------------
def worker(ip, queue, show_closed):
    while True:
        port = queue.get()
        if port is None:
            break

        scan_port(ip, port, show_closed)
        queue.task_done()


# -----------------------------
# Run scan session
# -----------------------------
def run_scan():
    target = input("\nTarget (IP or domain): ").strip()
    ip = resolve_target(target)

    if not ip:
        return

    print(f"\nResolved: {target} → {ip}")

    start_port = int(input("Start port: ").strip())
    end_port = int(input("End port: ").strip())

    print("\nMode:")
    print("1. Open only")
    print("2. Open + Closed\n")

    choice = input("Choose: ").strip()
    show_closed = (choice == "2")

    q = Queue()

    for port in range(start_port, end_port + 1):
        q.put(port)

    threads = []

    for _ in range(100):
        t = threading.Thread(target=worker, args=(ip, q, show_closed))
        t.start()
        threads.append(t)

    q.join()

    for _ in range(100):
        q.put(None)

    for t in threads:
        t.join()

    print("\n--- SCAN COMPLETE ---\n")


# -----------------------------
# Main menu loop
# -----------------------------
def main():
    while True:
        print("=== PORT SCANNER ===")
        print("1. New Scan")
        print("2. Exit\n")

        choice = input("Select: ").strip()

        if choice == "1":
            run_scan()
        elif choice == "2":
            print("Exiting...")
            break
        else:
            print("Invalid option\n")


if __name__ == "__main__":
    main()
