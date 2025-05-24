import socket  # For network connections
import threading  # For concurrent scanning
from queue import Queue  # Thread-safe queue to manage port tasks
import time  # To track scan duration
from datetime import datetime  # For timestamps
from colorama import Fore, Style, init  # For colored console output

init()  # Initialize colorama for cross-platform color support

# -----------------------
# Configuration
# -----------------------
MAX_THREADS = 100  # Number of threads for parallel scanning
open_ports = []  # Store open ports and banners
q = Queue()  # Queue of ports to be scanned
print_lock = threading.Lock()  # Prevent mixed output from threads
output_file = "scan_results.txt"  # File to save scan results

# -----------------------
# Banner Grabbing
# -----------------------
def grab_banner(ip, port):
    """Try to retrieve service banner from the open port."""
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode().strip()
        return banner
    except:
        return None

# -----------------------
# Port Scanning Logic
# -----------------------
def scan_port(port, target):
    """Attempts to connect to a port; logs if open and grabs banner."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))  # Returns 0 if port is open
        if result == 0:
            banner = grab_banner(target, port)
            with print_lock:  # Thread-safe output
                print(f"{Fore.GREEN}[+] Port {port} is OPEN{Style.RESET_ALL}")
                if banner:
                    print(f"    ↳ Banner: {banner}")
                open_ports.append((port, banner))
        s.close()
    except:
        pass

def threader(target):
    """Worker function to continuously scan ports from the queue."""
    while True:
        port = q.get()
        scan_port(port, target)
        q.task_done()

# -----------------------
# Main Program
# -----------------------
def main():
    # Get target IP or hostname
    target = input("Enter target IP or hostname: ")
    try:
        target_ip = socket.gethostbyname(target)
    except:
        print("Invalid hostname.")
        return

    print(f"\n{Fore.CYAN}Starting scan on {target_ip} at {datetime.now()}{Style.RESET_ALL}")

    # -----------------------
    # Choose scan profile
    # -----------------------
    print("\nChoose scan profile:")
    print("  1. Quick Scan")
    print("  2. Web Scan")
    print("  3. Full TCP (1–1024)")
    print("  4. Custom Range")
    choice = input("Enter choice [1-4]: ")

    if choice == "1":
        ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445]
    elif choice == "2":
        ports = [80, 443, 8080, 8443]
    elif choice == "3":
        ports = list(range(1, 1025))
    elif choice == "4":
        try:
            start_port = int(input("Enter start port: "))
            end_port = int(input("Enter end port: "))
            ports = list(range(start_port, end_port + 1))
        except ValueError:
            print("Invalid port range.")
            return
    else:
        print("Invalid option.")
        return

    # -----------------------
    # Start threaded scan
    # -----------------------
    start_time = time.time()

    for _ in range(MAX_THREADS):
        t = threading.Thread(target=threader, args=(target_ip,))
        t.daemon = True  # Dies when main thread exits
        t.start()

    for port in ports:
        q.put(port)  # Add port to queue

    q.join()  # Wait for queue to empty (all ports scanned)

    duration = time.time() - start_time
    print(f"\n{Fore.YELLOW}Scan completed in {duration:.2f} seconds.{Style.RESET_ALL}")

    # -----------------------
    # Save results to file
    # -----------------------
    with open(output_file, "w") as f:
        f.write(f"Scan results for {target_ip}\n")
        for port, banner in open_ports:
            f.write(f"Port {port} OPEN\n")
            if banner:
                f.write(f"    ↳ Banner: {banner}\n")

    print(f"{Fore.BLUE}Results saved to {output_file}{Style.RESET_ALL}")

# -----------------------
# Entry Point
# -----------------------
if __name__ == "__main__":
    main()
