import socket
import time

BROADCAST_ADDRESS = "255.255.255.255"
BROADCAST_PORT = 5012
BATTLE_CRY = b'Calling All Miras...'

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while True:
    print("calling out to: ", BROADCAST_ADDRESS, BROADCAST_PORT)
    udp.sendto(BATTLE_CRY, (BROADCAST_ADDRESS, BROADCAST_PORT))
    time.sleep(1)
    # udp.close()

while True:
    client.bind(("localhost", 5015))
    data = client.recv(4092)
    print("data!", data)

# client.close()
