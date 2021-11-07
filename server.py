import binascii
import socket
import sys
from ipaddress import IPv4Address

import DNSMessage


class Server:
    def main(self):
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind(("127.0.0.1", 53))
            while True:
                data, address = server.recvfrom(4096)
                request = DNSMessage.Message(data)

                if request.queries[0].type == b'\x00\x01':
                    response = self.get_response(request)

                    if response:
                        response.additional_records = []
                        response.authorities = []
                    else:
                        request.header.flags.qr = '1'
                        response = request
                    server.sendto(response.build(), address)
                    for answer in response.answers:
                        print(self.make_ip(answer.address))
        except KeyboardInterrupt:
            sys.exit(1)

    def get_response(self, request):
        data = request.build()

        response = self.send_message(data, ("a.root-servers.net", 53))
        query_name = request.queries[0].name
        query_type = request.queries[0].type

        while response:
            message = DNSMessage.Message(response)
            for answer in message.answers:
                if answer.type == query_type and answer.real_name == query_name:
                    return message
            if len(message.authorities) == 0:
                break
            for authority in message.authorities:
                if authority.type == b'\x00\x02' and authority.name != "":
                    address = self.make_address(authority.real_name_server)
                    print(address)
                    response = self.send_message(data, (address, 53))
                    break
        return None

    def send_message(self, message, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message, address)
        data, _ = sock.recvfrom(4096)

        sock.close()

        return data

    def make_address(self, address):
        res = []
        cur = b''
        length = 0
        isLetter = False
        i = 0
        for byte in address:
            if isLetter:
                cur += byte.to_bytes(1, 'big')
                i += 1
                if i == length:
                    i = 0
                    res.append(cur.decode())
                    cur = b''
                    isLetter = False
            else:
                length = byte
                isLetter = True

        return '.'.join(res)

    def make_ip(self, bytes):
        ip = []
        for byte in bytes:
            ip.append(str(byte))
        return '.'.join(ip)


def main():
    server = Server()
    server.main()


main()
