# GUI framework for building the app interface
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
# For creating network connections (TCP/UDP)
import socket
# Used to run scans in parallel for faster performance
import threading
from queue import Queue
from datetime import datetime
# For exporting results to CSV
import csv
# For exporting results to JSON
import json
# Used to make HTTP requests for IP geolocation
import requests

# Maximum number of worker threads to use
MAX_THREADS = 100
q = Queue()
open_ports = []
scan_results = {"start": None, "end": None, "target": None, "ports": [], "open_ports": []}

# Common vulnerable ports and associated risks
VULNERABLE_PORTS = {
    21: "FTP (insecure)", 23: "Telnet (no encryption)", 25: "SMTP (relay abuse)",
    135: "RPC (malware target)", 139: "NetBIOS (Windows vuln)", 445: "SMB (WannaCry)",
    1433: "MS SQL (brute-force)", 3389: "RDP (ransomware)"
}


# Attempt to capture service banner from open port
def grab_banner(ip, port):
    try:
        s = socket.socket()
        s.settimeout(2)
        s.connect((ip, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        return banner
    except:
        return None


# Perform a TCP port scan
def tcp_scan(target, port, tree, progress_var):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        if result == 0:
            banner = grab_banner(target, port)
# Common vulnerable ports and associated risks
            warning = VULNERABLE_PORTS.get(port, "")
            note = f"{banner or ''}"
            if warning:
                note += f" ⚠️ {warning}"
            open_ports.append((port, "TCP", note))
            tree.insert("", "end", values=(port, "TCP", "OPEN", note), tags=("vuln",) if warning else ())
        else:
            tree.insert("", "end", values=(port, "TCP", "Closed", ""))
    except:
        pass
    finally:
        progress_var.set(progress_var.get() + 1)


# Perform a UDP port scan
def udp_scan(target, port, tree, progress_var):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.sendto(b"", (target, port))
        try:
            data, _ = s.recvfrom(1024)
            note = data.decode(errors="ignore").strip() or "Response received"
            open_ports.append((port, "UDP", note))
            tree.insert("", "end", values=(port, "UDP", "OPEN*", note))
        except socket.timeout:
            tree.insert("", "end", values=(port, "UDP", "Unknown", "No response"))
    except:
        pass
    finally:
        progress_var.set(progress_var.get() + 1)


# Worker thread that fetches ports from queue and scans them
def worker(target, tree, progress_var, protocol):
    while not q.empty():
        port = q.get()
        if protocol == "TCP":
            tcp_scan(target, port, tree, progress_var)
        elif protocol == "UDP":
            udp_scan(target, port, tree, progress_var)
        elif protocol == "Both":
            tcp_scan(target, port, tree, progress_var)
            udp_scan(target, port, tree, progress_var)
        q.task_done()


# Retrieve IP geolocation and ISP info
def get_ip_info(ip):
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = res.json()
        return f"{data.get('country', '?')} | {data.get('org', '?')} | {data.get('as', '?')}"
    except:
        return "Geo lookup failed"


# Main scan initialization function: populates the queue, launches threads
def start_scan(target, ports, tree, progress_var, start_btn, geo_label, protocol, root):
    open_ports.clear()
    scan_results["start"] = datetime.now()
    scan_results["target"] = target
    scan_results["ports"] = ports
    scan_results["open_ports"].clear()
    tree.delete(*tree.get_children())
    progress_var.set(0)
    start_btn.config(state="disabled")

    if target != "127.0.0.1" and "localhost" not in target:
        geo_label.config(text="Looking up IP info...")
        threading.Thread(target=lambda: geo_label.config(text=get_ip_info(target))).start()

    for port in ports:
        q.put(port)

# Maximum number of worker threads to use
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker, args=(target, tree, progress_var, protocol))
        t.daemon = True
        t.start()

    def finish_scan():
        q.join()
        scan_results["end"] = datetime.now()
        scan_results["open_ports"] = open_ports[:]
        start_btn.config(state="normal")
        show_toast(root)

    threading.Thread(target=finish_scan).start()


# Display a temporary toast-style completion message
def show_toast(root):
    toast = ttk.Label(root, text="✅ Scan complete! You may now save your report.", foreground="green", font=("Segoe UI", 10, "bold"))
    toast.pack(pady=5)
    root.after(5000, toast.destroy)


# Save scan results to CSV or JSON
def export_results():
    if not scan_results["open_ports"]:
        messagebox.showwarning("Export", "No results to export.")
        return

    file = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv"), ("JSON", "*.json")])
    if not file:
        return

    if file.endswith(".csv"):
        with open(file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(["Port", "Protocol", "Status", "Banner/Warning"])
            for port, proto, note in scan_results["open_ports"]:
                writer.writerow([port, proto, "OPEN", note])
    elif file.endswith(".json"):
        export_data = {
            "target": scan_results["target"],
            "start": scan_results["start"].isoformat(),
            "end": scan_results["end"].isoformat(),
            "ports_scanned": len(scan_results["ports"]),
            "open_ports": [{"port": port, "protocol": proto, "info": note} for port, proto, note in scan_results["open_ports"]]
        }
        with open(file, "w") as f:
            json.dump(export_data, f, indent=4)


# Get the local IP address of this machine
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except:
        return "127.0.0.1"


# Build the GUI interface using tkinter and ttk
def main_gui():
    root = tk.Tk()
    root.title("Enhanced TCP/UDP Hybrid Scanner")
    root.geometry("850x700")

    canvas = tk.Canvas(root)
    scrollbar = ttk.Scrollbar(root, orient="vertical", command=canvas.yview)
    scroll_frame = ttk.Frame(canvas)

    scroll_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
    )

    canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
    canvas.configure(yscrollcommand=scrollbar.set)

    canvas.pack(side="left", fill="both", expand=True)
    scrollbar.pack(side="right", fill="y")

    ttk.Label(scroll_frame, text="Target IP or Hostname:").pack(pady=5)

    ip_frame = ttk.Frame(scroll_frame)
    ip_frame.pack(pady=2)

    ip_entry = ttk.Entry(ip_frame, width=40)
    ip_entry.pack(side=tk.LEFT)

    def autofill_ip():
        ip_entry.delete(0, tk.END)
        ip_entry.insert(0, get_local_ip())

    ttk.Button(ip_frame, text="📍 Use My IP", command=autofill_ip).pack(side=tk.LEFT, padx=5)

    geo_label = ttk.Label(scroll_frame, text="Geo Info: N/A")
    geo_label.pack(pady=5)

    ttk.Label(scroll_frame, text="Scan Profile:").pack(pady=5)
    profile_combo = ttk.Combobox(scroll_frame, values=["Quick", "Web", "Full", "Custom"], state="readonly")
    profile_combo.pack()

    port_frame = ttk.Frame(scroll_frame)
    ttk.Label(port_frame, text="Start Port:").pack(side=tk.LEFT)
    start_entry = ttk.Entry(port_frame, width=6)
    start_entry.pack(side=tk.LEFT, padx=5)
    ttk.Label(port_frame, text="End Port:").pack(side=tk.LEFT)
    end_entry = ttk.Entry(port_frame, width=6)
    end_entry.pack(side=tk.LEFT, padx=5)
    port_frame.pack(pady=5)

    protocol_var = tk.StringVar(value="TCP")
    protocol_frame = ttk.Frame(scroll_frame)
    ttk.Label(protocol_frame, text="Scan Protocol:").pack(side=tk.LEFT)
    for p in ["TCP", "UDP", "Both"]:
        ttk.Radiobutton(protocol_frame, text=p, variable=protocol_var, value=p).pack(side=tk.LEFT)
    protocol_frame.pack(pady=5)

    tree = ttk.Treeview(scroll_frame, columns=("Port", "Protocol", "Status", "Banner"), show="headings", height=18)
    for col in ["Port", "Protocol", "Status", "Banner"]:
        tree.heading(col, text=col)
    tree.tag_configure("vuln", background="#FFDDDD")
    tree.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

    progress_var = tk.IntVar()
    progress_bar = ttk.Progressbar(scroll_frame, maximum=100, variable=progress_var, length=500, mode="determinate")
    progress_bar.pack(pady=5)


    # Handles Start Scan button click, sets scan profile and starts scanning
    def on_start():
        target = ip_entry.get().strip()
        profile = profile_combo.get()
        proto = protocol_var.get()
        try:
            socket.gethostbyname(target)
        except:
            messagebox.showerror("Error", "Invalid IP or hostname.")
            return

        if profile == "Quick":
            ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445]
        elif profile == "Web":
            ports = [80, 443, 8080, 8443]
        elif profile == "Full":
            ports = list(range(1, 1025))
        elif profile == "Custom":
            try:
                start = int(start_entry.get())
                end = int(end_entry.get())
                ports = list(range(start, end + 1))
            except:
                messagebox.showerror("Error", "Invalid port range.")
                return
        else:
            messagebox.showerror("Error", "Select a scan profile.")
            return

        progress_bar.config(maximum=len(ports) * (2 if proto == "Both" else 1))
        start_scan(target, ports, tree, progress_var, start_btn, geo_label, proto, root)

    ttk.Label(scroll_frame, text="Available Actions Below:", font=("Segoe UI", 10, "bold")).pack(pady=10)
    button_frame = ttk.Frame(scroll_frame)
    start_btn = ttk.Button(button_frame, text="🚀 Start Scan", command=on_start)
    start_btn.pack(side=tk.LEFT, padx=10)
    ttk.Button(button_frame, text="💾 Save Report", command=export_results).pack(side=tk.LEFT, padx=10)
    button_frame.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main_gui()
