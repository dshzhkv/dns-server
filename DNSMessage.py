import binascii


def get_name_length(data):
    length = 0
    for i in range(len(data)):
        if data[i:i + 1] == b"\x00":
            length = i + 1
            break
        if data[i: i + 1] == b"\xc0":
            length = i + 2
            break
    return length


class Flags:
    def __init__(self, data):
        bits = bin(int(binascii.hexlify(data).decode(), 16))[2:].zfill(16)
        self.qr = bits[0]
        self.opcode = bits[1:5]
        self.aa = bits[5]
        self.tc = bits[6]
        self.rd = '1'
        self.ra = bits[8]
        self.z = '000'
        self.rcode = '0000'

    @staticmethod
    def make_byte(string):
        return int(string, 2).to_bytes(1, byteorder='big')

    def build(self):
        return self.make_byte(
            self.qr + self.opcode + self.aa + self.tc + self.rd) + \
               self.make_byte(self.ra + self.z + self.rcode)


class Header:
    def __init__(self, data):
        self.transaction_id = data[:2]
        self.flags = Flags(data[2:4])
        self.qdcount = data[4:6]
        self.ancount = data[6:8]
        self.nscount = data[8:10]
        self.arcount = data[10:12]

    def build(self):
        return self.transaction_id + self.flags.build() + self.qdcount + \
               self.ancount + self.nscount + self.arcount


class Query:
    def __init__(self, data):
        self.data = data

        self.length = 0

        self.name, self.type, self.Class = self.get_query()

    def get_query(self):
        i = get_name_length(self.data)

        name = self.data[:i]
        Type = self.data[i:i + 2]
        Class = self.data[i + 2:i + 4]
        self.length = i + 4
        return name, Type, Class

    def build(self):
        return self.name + self.type + self.Class


class Answer:
    def __init__(self, data):
        self.data = data

        self.length = 0

        self.name, self.type, self.Class, self.time, self.data_length, \
        self.address = self.get_answer()

        self.real_name = self.name

    def get_answer(self):
        i = get_name_length(self.data)

        name = self.data[:i]
        Type = self.data[i:i + 2]
        Class = self.data[i + 2:i + 4]
        time = self.data[i + 4:i + 8]
        data_length = self.data[i + 8:i + 10]
        address = b''
        for j in range(int.from_bytes(data_length, 'big')):
            address += self.data[i + 10 + j].to_bytes(1, 'big')

        self.length = i + 10 + int.from_bytes(data_length, 'big')

        return name, Type, Class, time, data_length, address

    def build(self):
        return self.name + self.type + self.Class + self.time + \
               self.data_length + self.address


class AuthoritativeNameserver:
    def __init__(self, data):
        self.data = data

        self.length = 0

        self.name, self.type, self.Class, self.time, self.data_length, \
        self.name_server = self.get_authority()

        self.real_name = self.name
        self.real_name_server = self.name_server

    def get_authority(self):
        i = get_name_length(self.data)
        name = self.data[:i]
        Type = self.data[i:i + 2]
        Class = self.data[i + 2:i + 4]
        time = self.data[i + 4:i + 8]
        data_length = self.data[i + 8:i + 10]
        name_server = b''
        for j in range(int.from_bytes(data_length, 'big')):
            name_server += self.data[i + 10 + j].to_bytes(1, 'big')

        self.length = i + 10 + int.from_bytes(data_length, 'big')

        return name, Type, Class, time, data_length, name_server

    def build(self):
        return self.name + self.type + self.Class + self.time + \
               self.data_length + self.name_server


class AdditionalRecords:
    def __init__(self, data):
        self.data = data

        self.length = 0

        self.name, self.type, self.Class, self.time, self.data_length, \
        self.address = self.get_record()

    def get_record(self):
        i = get_name_length(self.data)
        name = self.data[:i]
        Type = self.data[i:i + 2]
        Class = self.data[i + 2:i + 4]
        time = self.data[i + 4:i + 8]
        data_length = self.data[i + 8:i + 10]

        address = b''
        for j in range(int.from_bytes(data_length, 'big')):
            address += self.data[i + 10 + j].to_bytes(1, 'big')

        self.length = i + 10 + int.from_bytes(data_length, 'big')

        return name, Type, Class, time, data_length, address

    def build(self):
        return self.name + self.type + self.Class + self.time + \
               self.data_length + self.address


class Message:
    def __init__(self, data):
        self.data = data

        self.header = Header(data[:12])
        self.queries, byte_index = self.get_queries(12)
        self.answers, byte_index = self.get_answers(byte_index)
        self.authorities, byte_index = self.get_authoritative_nameservers(
            byte_index)
        self.additional_records = self.get_additional_records(byte_index)

    def get_queries(self, byte_index):
        queries = []
        for i in range(int.from_bytes(self.header.qdcount, 'big')):
            query = Query(self.data[byte_index:])
            queries.append(query)
            byte_index += query.length
        return queries, byte_index

    def get_answers(self, byte_index):
        answers = []
        for i in range(int.from_bytes(self.header.ancount, 'big')):
            answer = Answer(self.data[byte_index:])
            answers.append(answer)
            byte_index += answer.length

            if answer.name == b'\xc0\x0c':
                answer.real_name = self.queries[0].name

        return answers, byte_index

    def get_authoritative_nameservers(self, byte_index):
        authorities = []
        for i in range(int.from_bytes(self.header.nscount, 'big')):
            authority = AuthoritativeNameserver(self.data[byte_index:])
            authorities.append(authority)
            byte_index += authority.length

            if authority.name == b'\xc0\x0c':
                authority.real_name = self.queries[0].name
            if authority.name_server[-2:-1] == b'\xc0':
                offset = int.from_bytes(authority.name_server[-1:], 'big')
                name_length = get_name_length(self.data[offset:])
                # print(f"name_server: {authority.name_server}")
                # print(f"query_name: {self.queries[0].name}")
                authority.real_name_server = authority.name_server[:-2] + self.data[offset:offset + name_length]
                # print(f"real_server: {authority.real_name_server}")

        return authorities, byte_index

    def get_additional_records(self, byte_index):
        additional_records = []
        for i in range(int.from_bytes(self.header.arcount, 'big')):
            record = AdditionalRecords(self.data[byte_index:])
            additional_records.append(record)
            byte_index += record.length
        return additional_records

    def build(self):
        message = self.header.build()
        for query in self.queries:
            message += query.build()
        for answer in self.answers:
            message += answer.build()
        for authority in self.authorities:
            message += authority.build()
        for record in self.additional_records:
            message += record.build()
        return message
