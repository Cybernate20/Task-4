import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading

class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Packet Sniffer")

        
        self.start_button = tk.Button(root, text="Start Sniffing", command=self.start_sniffing)
        self.start_button.pack(pady=10)

       
        self.stop_button = tk.Button(root, text="Stop Sniffing", command=self.stop_sniffing, state=tk.DISABLED)
        self.stop_button.pack(pady=10)

        
        self.text_area = scrolledtext.ScrolledText(root, width=80, height=20)
        self.text_area.pack(padx=10, pady=10)

      
        self.sniffing = False
        self.sniff_thread = None

    def packet_callback(self, packet):
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            protocol = packet[IP].proto
            payload = None

            
            if TCP in packet:
                payload = bytes(packet[TCP].payload)
            elif UDP in packet:
                payload = bytes(packet[UDP].payload)
            elif Raw in packet:
                payload = bytes(packet[Raw].load)

            
            self.text_area.insert(tk.END, f"Packet from {ip_src} to {ip_dst}\n")
            self.text_area.insert(tk.END, f"Protocol: {protocol}\n")

            if payload:
                self.text_area.insert(tk.END, f"Payload: {payload[:100]}... \n")  # Display first 100 bytes of payload
            self.text_area.insert(tk.END, "-"*60 + "\n")
            self.text_area.yview(tk.END)

    def start_sniffing(self):
       
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)

       
        self.interface = 'en0'  

        
        self.sniffing = True
        self.sniff_thread = threading.Thread(target=self.sniff_packets)
        self.sniff_thread.start()

    def stop_sniffing(self):
       
        self.stop_button.config(state=tk.DISABLED)
        self.start_button.config(state=tk.NORMAL)

        
        self.sniffing = False
        if self.sniff_thread is not None:
            self.sniff_thread.join()

    def sniff_packets(self):
        try:
            sniff(iface=self.interface, prn=self.packet_callback, filter="ip", store=0, stop_filter=lambda x: not self.sniffing)
        except PermissionError:
            self.text_area.insert(tk.END, "Permission denied: Run as root\n")

if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
