# ===============================
# backend.py - Honeypot Backend with SQLite Logging
# ===============================
# Listens on ports, logs to file, sends to frontend, and saves to SQLite.

import socket
import threading
import datetime
import json
import sys
import logging
import argparse
import sqlite3  # New for database

# Set up logging to file
logging.basicConfig(
    filename='honeypot.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Default ports to listen on
HONEYPOT_PORTS = [22, 80, 8080, 3306]

# Fake banners for deception
BANNERS = {
    22: b"SSH-2.0-OpenSSH_7.4\r\n",
    80: b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body>Welcome</body></html>",
    8080: b"HTTP/1.0 200 OK\r\n\r\nFake Honeypot Server",
    3306: b"\xff\x00\x00\x00\x0a5.7.31-log\x00\x08\x00\x00"
}

FRONTEND_COMM_IP = '127.0.0.1'
FRONTEND_COMM_PORT = 9999

# ===============================
# SQLite Setup
# ===============================
# Create or connect to database
conn = sqlite3.connect("honeypot.db", check_same_thread=False)
cursor = conn.cursor()

# Create table if not exists
cursor.execute('''
CREATE TABLE IF NOT EXISTS connections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    source_ip TEXT,
    source_port INTEGER,
    target_port INTEGER,
    hostname TEXT,
    message TEXT
)
''')
conn.commit()

# ===============================
# Parse CLI Args
# ===============================
def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('--ports', nargs='+', type=int, help='List of honeypot ports to listen on')
    return parser.parse_args()

# ===============================
# HoneypotTCPHandler
# ===============================
class HoneypotTCPHandler(threading.Thread):
    def __init__(self, port, event_callback=None):
        super().__init__()
        self.port = port
        self.event_callback = event_callback
        self.server_socket = None
        self.running = False

    def run(self):
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.running = True
            logging.info(f"Honeypot listening on port {self.port}")

            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                handler_thread = threading.Thread(target=self.handle_connection,
                                                  args=(client_sock, client_addr),
                                                  daemon=True)
                handler_thread.start()

        except Exception as e:
            logging.error(f"Exception in honeypot on port {self.port}: {e}")
        finally:
            if self.server_socket:
                self.server_socket.close()
                logging.info(f"Honeypot on port {self.port} stopped.")

    def handle_connection(self, client_sock, client_addr):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            hostname = socket.getfqdn(client_addr[0])
        except:
            hostname = "Unknown"

        banner_msg = "Sent banner" if self.port in BANNERS else "No banner sent"
        event = {
            'port': self.port,
            'source_ip': client_addr[0],
            'source_port': client_addr[1],
            'hostname': hostname,
            'timestamp': timestamp,
            'message': f"Connection from {client_addr[0]}:{client_addr[1]} on port {self.port}. {banner_msg}"
        }

        logging.info(event['message'])
        if self.event_callback:
            self.event_callback(event)

        # Save to SQLite
        cursor.execute('''
            INSERT INTO connections (timestamp, source_ip, source_port, target_port, hostname, message)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, client_addr[0], client_addr[1], self.port, hostname, event['message']))
        conn.commit()

        try:
            banner = BANNERS.get(self.port, b"")
            if banner:
                client_sock.sendall(banner)
            client_sock.settimeout(2)
            client_sock.recv(1024)
        except Exception:
            pass
        finally:
            client_sock.close()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

# ===============================
# FrontendEventServer
# ===============================
class FrontendEventServer(threading.Thread):
    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.client_sockets = []
        self.running = False
        self.lock = threading.Lock()

    def run(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(1)
        self.running = True
        logging.info(f"Frontend event server started on {self.ip}:{self.port}")

        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                logging.info(f"Frontend connected from {client_addr}")
                with self.lock:
                    self.client_sockets.append(client_sock)
                client_thread = threading.Thread(target=self.handle_frontend_client,
                                                 args=(client_sock,),
                                                 daemon=True)
                client_thread.start()
            except OSError:
                break
            except Exception as e:
                logging.error(f"Exception in frontend event server: {e}")

    def handle_frontend_client(self, client_sock):
        try:
            while self.running:
                data = client_sock.recv(1024)
                if not data:
                    break
        except Exception:
            pass
        finally:
            with self.lock:
                if client_sock in self.client_sockets:
                    self.client_sockets.remove(client_sock)
            client_sock.close()
            logging.info("Frontend disconnected")

    def send_event(self, event):
        event_json = json.dumps(event) + "\n"
        event_bytes = event_json.encode('utf-8')

        with self.lock:
            for client_sock in self.client_sockets[:]:
                try:
                    client_sock.sendall(event_bytes)
                except Exception:
                    self.client_sockets.remove(client_sock)
                    client_sock.close()

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        with self.lock:
            for sock in self.client_sockets:
                sock.close()
            self.client_sockets.clear()

# ===============================
# Main Entry
# ===============================
def main():
    args = parse_args()
    ports = args.ports if args.ports else HONEYPOT_PORTS

    frontend_server = FrontendEventServer(FRONTEND_COMM_IP, FRONTEND_COMM_PORT)
    frontend_server.start()

    honeypot_listeners = []
    for port in ports:
        hp = HoneypotTCPHandler(port, event_callback=frontend_server.send_event)
        hp.daemon = True
        hp.start()
        honeypot_listeners.append(hp)

    logging.info("Honeypot backend running. Press Ctrl+C to exit.")
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        logging.info("Shutting down honeypot backend...")
    finally:
        for hp in honeypot_listeners:
            hp.stop()
        frontend_server.stop()
        conn.close()
        sys.exit(0)

if __name__ == "__main__":
    main()
