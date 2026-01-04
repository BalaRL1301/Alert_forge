import socket
import json

UDP_IP = "127.0.0.1"
UDP_PORT = 5140
MESSAGE = "Test Log Message from Script"

print(f"Sending to {UDP_IP}:{UDP_PORT}")
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.sendto(MESSAGE.encode(), (UDP_IP, UDP_PORT))
print("Sent.")
