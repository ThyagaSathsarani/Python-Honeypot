# ===============================
# frontend.py - Honeypot Frontend GUI with DB Integration (Modified)
# ===============================

# Import necessary libraries for GUI, networking, file handling, and data visualization
import tkinter as tk #Desktop GUI
from tkinter import ttk, messagebox, filedialog
import threading
import socket # }
import json   # } Recieve data from backend server
import queue
import csv
import sqlite3
from datetime import datetime
from collections import Counter

# Import matplotlib(chart library) for chart plotting (with fallback error) 
#Because it's well-supported in Python and integrates with Tkinter using FigureCanvasTkAgg
try:
    import matplotlib #Draw charts
    matplotlib.use("TkAgg")
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg 
    import matplotlib.pyplot as plt
except ImportError as e:
    raise ImportError("Install matplotlib: pip install matplotlib") from e

# Main GUI application class for the honeypot frontend
class HoneypotFrontendApp(tk.Tk):
    def __init__(self, backend_ip='127.0.0.1', backend_port=9999): #Connect the backend server at localhost:9999
        # Initialize the GUI window and setup connection variables
        super().__init__()
        self.backend_ip = backend_ip
        self.backend_port = backend_port
        self.event_queue = queue.Queue()
        self.events = []

        self.title("Honeypot Frontend - 0 Events Logged")
        self.geometry("800x650")

        # Show a status message and initialize the GUI components (dialog box)
        self.after(200, lambda: messagebox.showinfo("Status", "Honeypot started. Waiting for events..."))
        self.setup_ui()

        # Start a separate thread to listen for backend events
        self.listener_thread = threading.Thread(target=self.backend_event_listener, daemon=True)
        self.listener_thread.start()
        self.after(1000, self.process_event_queue) 
        #Using this "after(1000" in Tkinter to refresh every second and check for new events in the queue, the GUI stay updated in real time

    # Build the GUI interface layout with tabs, buttons, tables, and charts
    def setup_ui(self):
        style = ttk.Style(self)
        style.theme_use('clam')

        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(main, text="Honeypot Dashboard", font=("Segoe UI", 16, "bold"))
        title.pack()

        self.status_var = tk.StringVar(value="Last event: None")
        status_label = ttk.Label(main, textvariable=self.status_var, font=("Segoe UI", 10))
        status_label.pack(pady=2)

        # Control buttons for exporting and clearing logs
        btn_frame = ttk.Frame(main)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Export Current Log to CSV", command=self.export_to_csv).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Clear Log", command=self.clear_log).pack(side=tk.LEFT, padx=5)

        # Setup notebook tabs for logs and charts
        self.tabs = ttk.Notebook(main)
        self.tabs.pack(fill=tk.BOTH, expand=True)

        self.tab_log = ttk.Frame(self.tabs)
        self.tab_src = ttk.Frame(self.tabs)
        self.tab_ports = ttk.Frame(self.tabs)

        self.tabs.add(self.tab_log, text="Connection Log")
        self.tabs.add(self.tab_src, text="Top IPs")
        self.tabs.add(self.tab_ports, text="Ports Hit")

        # Table to show connection logs
        cols = ("Timestamp", "Source IP", "Source Port", "Target Port", "Message")
        self.log_tree = ttk.Treeview(self.tab_log, columns=cols, show='headings')
        for col in cols:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, anchor="center", width=120 if col != "Message" else 320)
        self.log_tree.pack(fill=tk.BOTH, expand=True)

        # Charts for top source IPs and ports hit
        self.fig_src_ip, self.ax_src_ip = plt.subplots(figsize=(6, 4))
        self.canvas_src_ip = FigureCanvasTkAgg(self.fig_src_ip, master=self.tab_src)
        self.canvas_src_ip.get_tk_widget().pack(fill=tk.BOTH, expand=True)

        self.fig_ports, self.ax_ports = plt.subplots(figsize=(6, 4))
        self.canvas_ports = FigureCanvasTkAgg(self.fig_ports, master=self.tab_ports)
        self.canvas_ports.get_tk_widget().pack(fill=tk.BOTH, expand=True)

    # Listen to backend on a separate thread and receive event data
    def backend_event_listener(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((self.backend_ip, self.backend_port))
            sock.settimeout(1.0)
            buffer = ""

            # Continuously receive data and add parsed events to the queue
            while True:
                try:
                    data = sock.recv(4096)
                    if not data:
                        break
                    buffer += data.decode('utf-8')
                    while "\n" in buffer:
                        line, buffer = buffer.split("\n", 1)
                        if line.strip():
                            try:
                                event = json.loads(line.strip())
                                self.event_queue.put(event)
                            except json.JSONDecodeError:
                                continue
                except socket.timeout:
                    continue
                except Exception:
                    break
            sock.close()
        except Exception as e:
            messagebox.showerror("Connection Failed", f"Could not connect to backend: {e}") #Dialog box

    # Process the event queue and update GUI with new event data
    def process_event_queue(self):
        updated = False
        while not self.event_queue.empty():
            event = self.event_queue.get()
            self.events.append(event)
            self.add_event_to_log(event)
            updated = True

        # Update status and charts if new data arrived
        if updated:
            self.status_var.set(f"Last event: {datetime.now().strftime('%H:%M:%S')} | Total: {len(self.events)}")
            self.title(f"Honeypot Frontend - {len(self.events)} Events Logged")
            self.update_charts()

        self.after(1000, self.process_event_queue)

    # Add a single event to the log table with color tagging based on port
    def add_event_to_log(self, event):
        values = (
            event.get('timestamp', ''),
            event.get('source_ip', ''),
            event.get('source_port', ''),
            event.get('port', ''),
            event.get('message', '')
        )
        tag = f"port{event.get('port')}"
        self.log_tree.insert('', 'end', values=values, tags=(tag,))

        port = str(event.get('port'))
        if port == "22":
            self.log_tree.tag_configure(tag, background="#ffdddd")
        elif port == "80":
            self.log_tree.tag_configure(tag, background="#ddffdd")
        elif port == "8080":
            self.log_tree.tag_configure(tag, background="#ddddff")
        elif port == "3306":
            self.log_tree.tag_configure(tag, background="#f5de5f")

        self.log_tree.yview_moveto(1)

    # Generate bar and pie charts based on event data
    def update_charts(self):
        src_counts = Counter(e['source_ip'] for e in self.events)
        port_counts = Counter(str(e['port']) for e in self.events)

        self.ax_src_ip.clear()
        top_ips = src_counts.most_common(10)
        if top_ips:
            ips, counts = zip(*top_ips)
            self.ax_src_ip.bar(ips, counts, color='tomato')
        else:
            self.ax_src_ip.text(0.5, 0.5, 'No data yet', ha='center')
        self.ax_src_ip.set_title("Top Source IPs")
        self.ax_src_ip.tick_params(axis='x', rotation=45)
        self.fig_src_ip.tight_layout()
        self.canvas_src_ip.draw()

        self.ax_ports.clear()
        if port_counts:
            # Define colors for specific ports
            port_color_map = {
              '22': '#FF9999',    # light red for SSH
            '80': '#99FF99',    # light green for HTTP
            '8080': '#66B3FF',  # light blue for alternate HTTP
            '3306': '#FFD700'   # gold for MySQL
            }     
            # Match colors to actual ports in the data
            colors = [port_color_map.get(port, '#CCCCCC') for port in port_counts.keys()]  # default: grey

            # Draw pie chart with custom colors
            self.ax_ports.pie(
            port_counts.values(),
            labels=port_counts.keys(),
            autopct='%1.1f%%',
            startangle=90,
            colors=colors
            )

        else:
            self.ax_ports.text(0.5, 0.5, 'No data yet', ha='center')
        self.ax_ports.set_title("Ports Hit")
        self.fig_ports.tight_layout()
        self.canvas_ports.draw()

    # Export all collected events into a CSV file
    def export_to_csv(self):
        if not self.events:
            messagebox.showinfo("No Data", "No events to export.")
            return
        file = filedialog.asksaveasfilename(defaultextension=".csv",
                                            filetypes=[("CSV Files", "*.csv")]) #Dialog box to select file to save CSV.
        if file:
            with open(file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Source IP", "Source Port", "Target Port", "Message"])
                for e in self.events:
                    writer.writerow([
                        str(e.get('timestamp', '')).split(' ')[-1],
                        e.get('source_ip', ''),
                        e.get('source_port', ''),
                        e.get('port', ''),
                        e.get('message', '')
                    ])
            messagebox.showinfo("Exported", f"Log exported to {file}")

    # Clear the log table and reset the interface
    def clear_log(self):
        self.events.clear()
        for row in self.log_tree.get_children():
            self.log_tree.delete(row)
        self.update_charts()
        self.status_var.set("Last event: None")
        self.title("Honeypot Frontend - 0 Events Logged")

# Launch the GUI application
if __name__ == '__main__':
    app = HoneypotFrontendApp()
    app.mainloop()
