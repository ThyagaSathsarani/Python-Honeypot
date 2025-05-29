Honeypot System - Final Year Project

This project simulates a low-interaction honeypot system designed to detect, log, and visualize unauthorized access attempts on commonly targeted ports.

Contents:

backend.py         : Python script that runs the honeypot backend

frontend.py        : Python GUI application for live monitoring

honeypot.db        : SQLite database for logging events (auto-created)

checking_code.swift: Python snippet to simulate an attack (despite the name)

README.txt         : This instruction file

How to Run the Project

1. Requirements

Make sure you have Python 3 installed along with the following libraries:

tkinter (usually pre-installed)

matplotlib

sqlite3 (built-in)

socket, threading, queue, json, csv (all standard libraries)

To install matplotlib if needed:

pip install matplotlib

2. Running the System

Open two terminals (in the same VM or physical machine):

Terminal 1 – Start the backend:

python backend.py

Terminal 2 – Start the frontend GUI:

python frontend.py

The frontend dashboard will now be ready to receive and display events in real time.

3. Testing the Honeypot

To simulate an external attack attempt, a sample script is included: checking_code.swift.
Despite the .swift extension, it's a Python script and should be run as such.

Usage: Once both the backend and frontend are running, open a third terminal.

python checking_code.swift

Alternatively, open a Python interactive terminal and paste the code directly. You can run all the code at once or section by section. Each section simulates activity on a specific port.

Example (for port 22):

import socket

s = socket.create_connection(("127.0.0.1", 22), timeout=3)
print(s.recv(1024))
s.close()

You should immediately see entries appear in the frontend GUI — including source IP, port, and time.

4. Running in Virtual Machines

This project can be tested using any Virtual Machine platform such as VirtualBox or VMware.

To simulate realistic scenarios:

Run the honeypot on your host machine.

Run the testing script from a VM on the same network.

Ensure the VM uses either:

Bridged Adapter (same LAN as host)

Host-only Adapter + NAT combo (with IP forwarding if needed)

If Using a Linux VM:

Start the VM and log in.

Open a terminal and check the assigned IP:

ip a

Ensure the VM has an IP on the same subnet as the honeypot (e.g., 192.168.212.x).

Ping the honeypot machine:

ping 192.168.212.130

(To stop ping command ->  ctrl+c )

If ping is successful, you can test the honeypot using Python:

import socket
s = socket.create_connection(("192.168.212.130", 22), timeout=3)
print(s.recv(1024))
s.close()

This will trigger a log in the honeypot system.

Important Notes

All connection attempts are saved to the honeypot.db SQLite database.

You can export logs to CSV directly from the frontend GUI. (Using "Export Current Logs to CSV" button.)

The GUI uses color-coded rows to visually differentiate ports:

Red: SSH (22)

Green: HTTP (80)

Blue: Alt HTTP (8080)

Yellow: MySQL (3306)

This system was built to explore real-time monitoring, multithreading, network simulation, and security visualization in Python.

