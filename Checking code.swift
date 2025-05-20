"""
//Run this in python terminal (one section at a time)

import socket
s = socket.create_connection(("127.0.0.1", 22), timeout=3)
print(s.recv(1024))
s.close()

import socket
s = socket.create_connection(("127.0.0.1", 80), timeout=3)
print(s.recv(1024))
s.close()

import socket
s = socket.create_connection(("127.0.0.1", 8080), timeout=3)
print(s.recv(1024))
s.close()

import socket
s = socket.create_connection(("127.0.0.1", 3306), timeout=3)
print(s.recv(1024))
s.close()


"""