import socket
import sys

from DNSMessage import Message


class Server:
    def main(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind(("127.0.0.1", 53))

            while True:
                data, address = s.recvfrom(4096)
                request = Message(data)

                if request.queries[0].type == b'\x00\x01':
                    response = self.get_response(request)

                    if response:
                        response.additional_records = []
                        response.authorities = []
                    else:
                        request.header.flags.qr = '1'
                        response = request
                    s.sendto(response.build(), address)

        except KeyboardInterrupt:
            sys.exit(1)

    def get_response(self, request):
        request_build = request.build()

        data = self.send_message(request_build, ("a.root-servers.net", 53))

        query_name = request.queries[0].name
        query_type = request.queries[0].type

        while data:
            response = Message(data)
            for answer in response.answers:
                if answer.type == query_type and answer.real_name == query_name:
                    return response
            if len(response.authorities) == 0:
                break
            for authority in response.authorities:
                if authority.type == b'\x00\x02':
                    address = self.make_address(authority.real_address)
                    data = self.send_message(request_build, (address, 53))
                    break
        return None

    @staticmethod
    def send_message(message, address):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(message, address)
        data, _ = sock.recvfrom(4096)
        sock.close()

        return data

    @staticmethod
    def make_address(address):
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

    @staticmethod
    def make_ip(address):
        ip = []
        for byte in address:
            ip.append(str(byte))
        return '.'.join(ip)


if __name__ == '__main__':
    server = Server()
    server.main()
