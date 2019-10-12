import socket
import time

BROADCAST_ADDRESS = "255.255.255.255"
BROADCAST_PORT = 5012
BATTLE_CRY = b'Calling All Miras...'
MACHINE = 0

udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

while MACHINE == 0:
    print("calling out to: ", BROADCAST_ADDRESS, BROADCAST_PORT)
    print(BATTLE_CRY)
    udp.sendto(BATTLE_CRY, (BROADCAST_ADDRESS, BROADCAST_PORT))
    time.sleep(1)

    address, data = udp.recvfrom(65565)
    print("data!", data, address)
    # udp.close()

while True:
    data = client.recvfrom(5015)
    client.bind((INADDR_ANY, 5015))

    print("data!", data)
    time.sleep(1)

# client.close()
