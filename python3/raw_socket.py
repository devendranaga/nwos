import socket
from pkt_buffer import *
from eth import *

ETH_P_ALL = 3

class netos_raw_socket:
    def __init__(self, ifname):
        self.fd = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        self.fd.bind((ifname, 0))

    def recv(self):
        return self.fd.recv(65535)

    def send(self, buf):
        return self.fd.send(buf)

    def __exit__(self):
        self.fd.close()

if __name__ == "__main__":
    nr = netos_raw_socket("wlp4s0")

    while True:
        rx_buf = nr.recv()
        print("rx len: " + str(len(rx_buf)))

        pkt_buf = netos_pkt_buffer()
        pkt_buf.set_rx_buf(rx_buf)

        eh = netos_eth()
        eh.parse(pkt_buf)
        eh.print()
