# ===============================
# backend.py - Honeypot Backend with SQLite Logging
# ===============================
# Listens on ports, logs to file, sends to frontend, and saves to SQLite.

import socket #For networking - port listening.
import threading #Handle Multiple connections simultaneously.
import datetime
import json #Send data to frontend in JSON format.
import sys
import logging #Write messahges to a log file.
import argparse
import sqlite3  #Save data to a database.

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
    8080: b"HTTP/1.0 200 OK\r\n\r\nWeb Server",
    3306: b"\xff\x00\x00\x00\x0a5.7.31-log\x00\x08\x00\x00"
}

FRONTEND_COMM_IP = '127.0.0.1' # Connect the frontenf through IP for frontend communication
FRONTEND_COMM_PORT = 9999 # Port for frontend communication

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
# HoneypotTCPHandler (The realtime honeypot listner)
# ===============================

#Represents a TCP honeypot listener for a specific port.  
class HoneypotTCPHandler(threading.Thread): #Allows simultaneous connections and prevents blocking in multithreading.
    def __init__(self, port, event_callback=None):
        super().__init__()
        self.port = port
        self.event_callback = event_callback #Function to send data to frontend
        #Events are converted into JSON and sent over a TCP socket to the frontend, which listens continuously.(send data to frontend)
        self.server_socket = None
        self.running = False
        
    #Starts listening 

    #This starts a TCP server on the specified port(self port), accepting incoming connections.

    def run(self):
        try:
            #Socket creation.
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.running = True
            logging.info(f"Honeypot listening on port {self.port}")

            #This waits for a scanner to connect, and get their IP address.
            while self.running:
                try:
                    client_sock, client_addr = self.server_socket.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                #Main part of the honeypot 
                    # 1.gets called every time someone connects
                    # 2.gathers attacker data, logs it, sends it to the GUI
                    # 3.stores it in the database
                    #all from this one method
                #Start a new thread to handle the each incomming connection. SO multiple attackers don't block each other.
                handler_thread = threading.Thread(target=self.handle_connection, 
                #spawns a new thread for each connection using handle_connection(). This ensures concurrent logging and response when multiple attackers connect
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
        # Get current timestamp in the format YYYY-MM-DD HH:MM:SS
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
             # Try to get the hostname of the attacker's IP (may fail)
            hostname = socket.getfqdn(client_addr[0])
        except:
            hostname = "Unknown" # Set hostname as Unknown if resolution fails

        # Check if a fake banner is available for this port
        banner_msg = "Sent banner" if self.port in BANNERS else "No banner sent"
        # Create a dictionary to store event data
        event = {
            'port': self.port, # Port the attacker tried to connect to
            'source_ip': client_addr[0], # Attacker's IP address
            'source_port': client_addr[1], # Port number from attacker's side
            'hostname': hostname, # Hostname (if resolved)
            'timestamp': timestamp, # Time of the connection
            'message': f"Connection from {client_addr[0]}:{client_addr[1]} on port {self.port}. {banner_msg}"
        }

         # Log the connection event to honeypot.log file
        logging.info(event['message'])
         # If GUI is connected, send the event to be displayed in real time
        if self.event_callback:
            self.event_callback(event)


        # Save to SQLite
        cursor.execute('''
            INSERT INTO connections (timestamp, source_ip, source_port, target_port, hostname, message)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (timestamp, client_addr[0], client_addr[1], self.port, hostname, event['message']))
        conn.commit() # Commit changes to the database

        try:
            # Get the fake banner for the current port (if defined)
            banner = BANNERS.get(self.port, b"")
            if banner:
                client_sock.sendall(banner) # Send fake banner to attacker
            client_sock.settimeout(2) # Wait for any response (optional)
            client_sock.recv(1024) # Try to receive data (if any
        except Exception:
            pass # Ignore any errors from sending or receiving
        finally:
            client_sock.close() # Close the connection socket
        #Main part end here from the above line.

    def stop(self):
        self.running = False # Stop the listener loop
        if self.server_socket:
            self.server_socket.close() # Close the server socket

# ===============================
# FrontendEventServer
# ===============================
class FrontendEventServer(threading.Thread):
    # Initialize the server with IP, port, and setup for managing client connections
    def __init__(self, ip, port):
        super().__init__()
        self.ip = ip
        self.port = port
        self.server_socket = None
        self.client_sockets = []
        self.running = False
        self.lock = threading.Lock()

    # Start the frontend server and accept connections from GUI clients
    def run(self):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.ip, self.port))
        self.server_socket.listen(1)
        self.running = True
        logging.info(f"Frontend event server started on {self.ip}:{self.port}")

        # Accept frontend connections and handle each in a separate thread
        while self.running:
            try:
                client_sock, client_addr = self.server_socket.accept()
                logging.info(f"Frontend connected from {client_addr}")
                with self.lock:
                    self.client_sockets.append(client_sock)

                # Start a new thread to handle communication with this frontend client
                client_thread = threading.Thread(target=self.handle_frontend_client,
                                                 args=(client_sock,),
                                                 daemon=True)
                client_thread.start()
            except OSError:
                break
            except Exception as e:
                logging.error(f"Exception in frontend event server: {e}")

    # Manage the lifecycle of a connected frontend client
    def handle_frontend_client(self, client_sock):
        try:
            while self.running:
                data = client_sock.recv(1024)
                if not data:
                    break
        except Exception:
            pass
        finally:
            # Remove the client from the list and close the socket
            with self.lock:
                if client_sock in self.client_sockets:
                    self.client_sockets.remove(client_sock)
            client_sock.close()
            logging.info("Frontend disconnected")

    # Send a JSON-formatted event to all connected frontend clients
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

    # Stop the server and close all client connections
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
    # Parse command-line arguments (e.g., --ports 22 80 8080)
    args = parse_args()
    ports = args.ports if args.ports else HONEYPOT_PORTS

    # Start the frontend event server to send logs to the GUI in real time
    frontend_server = FrontendEventServer(FRONTEND_COMM_IP, FRONTEND_COMM_PORT)
    frontend_server.start()

    # Start honeypot listeners for each port in a separate thread
    honeypot_listeners = []
    for port in ports:
        hp = HoneypotTCPHandler(port, event_callback=frontend_server.send_event)
        hp.daemon = True
        hp.start()
        honeypot_listeners.append(hp)

    logging.info("Honeypot backend running. Press Ctrl+C to exit.")

    # Keep the main thread alive until interrupted
    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        logging.info("Shutting down honeypot backend...")
    finally:
        # Stop all honeypot listeners and frontend server, then clean up
        for hp in honeypot_listeners:
            hp.stop()
        frontend_server.stop()
        conn.close()
        sys.exit(0)

# Run the main function only when script is executed directly
if __name__ == "__main__":
    main()
