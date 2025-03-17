import tkinter as tk
from tkinter import scrolledtext, messagebox
import socket
import nmap
import shodan
import platform
import subprocess
import os
import threading


SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")

class NetworkScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Scanner & Vulnerability Checker")
        self.root.geometry("700x500")

        self.label_ip = tk.Label(root, text="Enter Network IP Range (e.g., 192.168.1.1/24):")
        self.label_ip.pack()
        self.entry_ip = tk.Entry(root, width=40)
        self.entry_ip.pack()

        self.scan_button = tk.Button(root, text="Scan Network", command=self.start_scan_thread)
        self.scan_button.pack()

        self.result_text = scrolledtext.ScrolledText(root, width=80, height=20)
        self.result_text.pack()

    def start_scan_thread(self):
        """Run the scan in a separate thread to prevent GUI freezing."""
        scan_thread = threading.Thread(target=self.scan_network, daemon=True)
        scan_thread.start()

    def scan_network(self):
        """Performs network scan and updates the GUI."""
        ip_range = self.entry_ip.get().strip()
        if not ip_range:
            messagebox.showwarning("Input Error", "Please enter a valid IP range.")
            return

        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Scanning Network: {ip_range}\n")
        self.result_text.insert(tk.END, "-" * 50 + "\n")

        devices = self.network_scan(ip_range)
        if not devices:
            self.result_text.insert(tk.END, "No active devices found.\n")
            return

        for device in devices:
            self.result_text.insert(tk.END, f"IP: {device['ip']}, MAC: {device['mac']}, Vendor: {device['vendor']}\n")

            open_ports = self.port_scan(device['ip'])
            self.result_text.insert(tk.END, f"Open Ports: {', '.join(map(str, open_ports)) if open_ports else 'None'}\n")

            os_info = self.detect_os(device['ip'])
            self.result_text.insert(tk.END, f"OS Detected: {os_info}\n")

            vuln_info = self.check_vulnerabilities(device['ip'])
            self.result_text.insert(tk.END, f"Vulnerabilities: {vuln_info}\n")
            self.result_text.insert(tk.END, "-" * 50 + "\n")

    def network_scan(self, ip_range):
        """Scans the network using ARP."""
        result = []
        cmd = ["arp", "-a"]
        try:
            output = subprocess.check_output(cmd, encoding="utf-8")
            for line in output.split("\n"):
                if "." in line and "dynamic" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        result.append({"ip": parts[0], "mac": parts[1], "vendor": "Unknown"})
        except Exception as e:
            print("[ERROR] Network scan failed:", e)
        return result

    def port_scan(self, ip):
        """Scans for open ports using Nmap with proper error handling."""
        scanner = nmap.PortScanner()
        try:
            scanner.scan(ip, '1-1024', '-Pn -sT')

            if ip not in scanner.all_hosts():
                return []

            if 'tcp' not in scanner[ip]:
                return []

            return [port for port in scanner[ip]['tcp'] if scanner[ip]['tcp'][port]['state'] == 'open']
        except Exception as e:
            print(f"[ERROR] Nmap Scan Failed for {ip}: {e}")
            return []

    def detect_os(self, ip):
        """Detects OS using Nmap. Uses alternative methods if Nmap fails."""
        scanner = nmap.PortScanner()
        try:
            scanner.scan(ip, arguments='-O')
            if ip in scanner.all_hosts() and 'osmatch' in scanner[ip]:
                return scanner[ip]['osmatch'][0]['name']
        except:
            pass
        return self.guess_os_from_ttl(ip)

    def guess_os_from_ttl(self, ip):
        """Estimates OS based on TTL (Time-To-Live) values."""
        try:
            result = subprocess.check_output(f"ping -n 1 {ip}", shell=True).decode()
            if "TTL=" in result:
                ttl_value = int(result.split("TTL=")[1].split()[0])
                return "Windows" if ttl_value > 64 else "Linux/Unix-based"
        except:
            return "OS detection failed"

    def check_vulnerabilities(self, ip):
        """Checks for known vulnerabilities using Shodan API. Only works for public IPs."""
        if not SHODAN_API_KEY:
            return "Shodan API key not set."

        
        private_ip_ranges = ["192.168.", "10.", "172."]
        if any(ip.startswith(r) for r in private_ip_ranges):
            ip = self.get_public_ip()
            if not ip:
                return "No public IP found for Shodan lookup."

        try:
            api = shodan.Shodan(SHODAN_API_KEY)
            host = api.host(ip)
            vuln_list = host.get('vulns', [])
            return "\n".join(vuln_list) if vuln_list else "No known vulnerabilities."
        except Exception as e:
            return f"Shodan Lookup Failed: {e}"

    def get_public_ip(self):
        """Fetches the public IP of the network."""
        try:
            return subprocess.check_output("curl -s https://api64.ipify.org", shell=True).decode().strip()
        except:
            return None


if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkScannerApp(root)
    root.mainloop()
