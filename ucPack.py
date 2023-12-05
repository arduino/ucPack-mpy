import struct

from CircularBuffer import CircularBuffer


class ucPack:

    def __init__(self, buffer_size: int, start_index: int = ord('A'), end_index: int = ord('#')):
        self.buffer_size = buffer_size
        self.buffer = CircularBuffer(buffer_size)
        self.start_index = start_index
        self.end_index = end_index

        self.payload = bytearray(buffer_size)

        self.msg = bytearray(buffer_size)
        self.msg_size = 0

    def checkPayload(self) -> bool:
        """
        Parses and checks the buffer to get the payload
        :return:
        """

        # check if buffer is empty
        if self.buffer.isEmpty():
            return False

        # check the index byte
        while not (self.buffer.top() == self.start_index) and (self.buffer.getSize() > 0):
            self.buffer.pop()

        # exit if only message index is received
        if self.buffer.getSize() <= 1:
            return False

        # get the payload dimension
        payload_size = self.buffer[1]

        # check if packet is complete
        if self.buffer.getSize() < (payload_size + 4):     # memo: index|length|msg|stop|crc8
            return False

        # check if stop byte is correct
        if self.buffer[payload_size + 2] != self.end_index:
            return False

        # crc checking
        for i in range(0, payload_size):
            self.payload[i] = self.buffer[i + 2]

        if self.crc8(self.payload[0:payload_size]) != self.buffer[payload_size + 3]:
            self.buffer.pop()   # delete the index so it is possible to recheck
            return False

        # clear the buffer
        for _ in range(0, payload_size + 4):
            self.buffer.pop()

        return True

    @staticmethod
    def crc8(data: [int]) -> int:
        """
        Calculates the CRC8-MAXIM of the data array
        :param data: the input data array
        :return: the calculated crc
        """

        crc = 0x00

        for extract in data:
            for _ in range(0, 8):
                sum = (crc ^ extract) & 0x01
                crc = crc >> 1
                if sum:
                    crc = crc ^ 0x8C
                extract = extract >> 1

        return crc

    def payloadTop(self):
        """
        Returns the top element of the payload array
        :return:
        """

        return self.payload[0]

    def packetC1B(self, code: int, b: int) -> int:
        """
        Packets the byte b with command code + start and end indexes
        :param code:
        :param b: the 'byte' to packet
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 2
        self.msg[2] = code & 0xFF
        self.msg[3] = b & 0xFF
        self.msg[4] = self.end_index & 0xFF
        self.msg[5] = self.crc8(self.msg[2:4])
        self.msg_size = 6
        return self.msg_size

    def unpacketC1B(self) -> (int, int):
        """
        Unpackets the payload expecting a command code and one byte
        :return: code and byte
        """

        code = self.payload[0]
        b = self.payload[1]
        return code, b

    def packetC2B(self, code: int, b1: int, b2: int) -> int:
        """
        Packets bytes b1 and b2 with command code + start and end indexes
        :param code:
        :param b1: first 'byte' to packet
        :param b2: second 'byte' to packet
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 3
        self.msg[2] = code & 0xFF
        self.msg[3] = b1 & 0xFF
        self.msg[4] = b2 & 0xFF
        self.msg[5] = self.end_index & 0xFF
        self.msg[6] = self.crc8(self.msg[2:5])
        self.msg_size = 7
        return self.msg_size

    def unpacketC2B(self) -> (int, int, int):
        """
        Unpackets the payload expecting a command code and two bytes
        :return: code and bytes
        """

        code = self.payload[0]
        b1 = self.payload[1]
        b2 = self.payload[2]
        return code, b1, b2

    def packetC3B(self, code: int, b1: int, b2: int, b3: int) -> int:
        """
        Packets bytes b1, b2 and b3 with command code + start and end indexes
        :param code:
        :param b1: first 'byte' to packet
        :param b2: second 'byte' to packet
        :param b3: third 'byte' to packet
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 4
        self.msg[2] = code & 0xFF
        self.msg[3] = b1 & 0xFF
        self.msg[4] = b2 & 0xFF
        self.msg[5] = b3 & 0xFF
        self.msg[6] = self.end_index & 0xFF
        self.msg[7] = self.crc8(self.msg[2:6])
        self.msg_size = 8
        return self.msg_size

    def unpacketC3B(self) -> (int, int, int, int):
        """
        Unpackets the payload expecting a command code and three bytes
        :return: code and bytes
        """

        code = self.payload[0]
        b1 = self.payload[1]
        b2 = self.payload[2]
        b3 = self.payload[3]
        return code, b1, b2, b3

    def packetC1F(self, code: int, f: float) -> int:
        """
        Packets the float f with command code + start and end indexes
        :param code:
        :param f:
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 5
        self.msg[2] = code & 0xFF
        self.msg[3:7] = bytearray(struct.pack("f", f))
        self.msg[7] = self.end_index & 0xFF
        self.msg[8] = self.crc8(self.msg[2:7])
        self.msg_size = 9
        return self.msg_size

    def unpacketC1F(self) -> (int, float):
        """
        Unpackets the payload expecting a command code and one float
        :return: code and float number
        """

        code = self.payload[0]
        f = struct.unpack("f", self.payload[1:5])[0]
        return code, f

    def packetC2F(self, code: int, f1: float, f2: float) -> int:
        """
        Packets the floats f1, f2 with command code + start and end indexes
        :param code:
        :param f1:
        :param f2:
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 9
        self.msg[2] = code & 0xFF
        self.msg[3:7] = bytearray(struct.pack("f", f1))
        self.msg[7:11] = bytearray(struct.pack("f", f2))
        self.msg[11] = self.end_index & 0xFF
        self.msg[12] = self.crc8(self.msg[2:11])
        self.msg_size = 13
        return self.msg_size

    def unpacketC2F(self) -> (int, float, float):
        """
        Unpackets the payload expecting a command code and two floats
        :return: code, f1, f2
        """

        code = self.payload[0]
        f1 = struct.unpack("f", self.payload[1:5])[0]
        f2 = struct.unpack("f", self.payload[5:9])[0]
        return code, f1, f2

    def packetC4F(self, code: int, f1: float, f2: float, f3: float, f4: float) -> int:
        """
        Packets the floats f1, f2, f3, f4 with command code + start and end indexes
        :param code:
        :param f1:
        :param f2:
        :param f3:
        :param f4:
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 17
        self.msg[2] = code & 0xFF
        self.msg[3:7] = bytearray(struct.pack("f", f1))
        self.msg[7:11] = bytearray(struct.pack("f", f2))
        self.msg[11:15] = bytearray(struct.pack("f", f3))
        self.msg[15:19] = bytearray(struct.pack("f", f4))
        self.msg[19] = self.end_index & 0xFF
        self.msg[20] = self.crc8(self.msg[2:19])
        self.msg_size = 21
        return self.msg_size

    def unpacketC4F(self) -> (int, float, float, float, float):
        """
        Unpackets the payload expecting a command code and 4 floats
        :return: code, f1, f2, f3, f4
        """

        code = self.payload[0]
        f1 = struct.unpack("f", self.payload[1:5])[0]
        f2 = struct.unpack("f", self.payload[5:9])[0]
        f3 = struct.unpack("f", self.payload[9:13])[0]
        f4 = struct.unpack("f", self.payload[13:17])[0]
        return code, f1, f2, f3, f4

    def packetC8F(self, code: int, f1: float, f2: float, f3: float, f4: float,
                  f5: float, f6: float, f7: float, f8: float) -> int:
        """
        Packets the floats f1, f2, f3, f4, f5, f6, f7, f8 with command code + start and end indexes
        :param code:
        :param f1:
        :param f2:
        :param f3:
        :param f4:
        :param f5:
        :param f6:
        :param f7:
        :param f8:
        :return: returns the size of the resulting msg array
        """

        self.msg[0] = self.start_index & 0xFF
        self.msg[1] = 33
        self.msg[2] = code & 0xFF
        self.msg[3:7] = bytearray(struct.pack("f", f1))
        self.msg[7:11] = bytearray(struct.pack("f", f2))
        self.msg[11:15] = bytearray(struct.pack("f", f3))
        self.msg[15:19] = bytearray(struct.pack("f", f4))
        self.msg[19:23] = bytearray(struct.pack("f", f5))
        self.msg[23:27] = bytearray(struct.pack("f", f6))
        self.msg[27:31] = bytearray(struct.pack("f", f7))
        self.msg[31:35] = bytearray(struct.pack("f", f8))
        self.msg[35] = self.end_index & 0xFF
        self.msg[36] = self.crc8(self.msg[2:35])
        self.msg_size = 37
        return self.msg_size

    def unpacketC8F(self) -> (int, float, float, float, float, float, float, float, float):
        """
        Unpackets the payload expecting a command code and 8 floats
        :return: code, f1, f2, f3, f4, f5, f6, f7, f8
        """

        code = self.payload[0]
        f1 = struct.unpack("f", self.payload[1:5])[0]
        f2 = struct.unpack("f", self.payload[5:9])[0]
        f3 = struct.unpack("f", self.payload[9:13])[0]
        f4 = struct.unpack("f", self.payload[13:17])[0]
        f5 = struct.unpack("f", self.payload[17:21])[0]
        f6 = struct.unpack("f", self.payload[21:25])[0]
        f7 = struct.unpack("f", self.payload[25:29])[0]
        f8 = struct.unpack("f", self.payload[29:33])[0]
        return code, f1, f2, f3, f4, f5, f6, f7, f8


if __name__ == "__main__":
    packeter = ucPack(buffer_size=10, start_index=ord('A'), end_index=ord('#'))
    data = bytearray([ord('X'), 0x11])
    c = ucPack.crc8(data)
    packeter.buffer.push(ord('A'))
    packeter.buffer.push(2)
    packeter.buffer.push(ord('X'))
    packeter.buffer.push(0x11)
    packeter.buffer.push(ord('#'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC1B())

    code_, byte_ = packeter.unpacketC1B()

    packeter.packetC1B(code_, byte_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]

    packeter = ucPack(buffer_size=10, start_index=ord('A'), end_index=ord('#'))
    data = bytearray([ord('X'), 0x11, 0x12])
    c = ucPack.crc8(data)
    packeter.buffer.push(ord('A'))
    packeter.buffer.push(3)
    packeter.buffer.push(ord('X'))
    packeter.buffer.push(0x11)
    packeter.buffer.push(0x12)
    packeter.buffer.push(ord('#'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC2B())

    code_, byte1_, byte2_ = packeter.unpacketC2B()

    packeter.packetC2B(code_, byte1_, byte2_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]

    packeter = ucPack(buffer_size=10, start_index=ord('A'), end_index=ord('#'))
    data = bytearray([ord('X'), 0x11, 0x12, 0x15])
    c = ucPack.crc8(data)
    packeter.buffer.push(ord('A'))
    packeter.buffer.push(4)
    packeter.buffer.push(ord('X'))
    packeter.buffer.push(0x11)
    packeter.buffer.push(0x12)
    packeter.buffer.push(0x15)
    packeter.buffer.push(ord('#'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC3B())

    code_, byte1_, byte2_, byte3_ = packeter.unpacketC3B()

    packeter.packetC3B(code_, byte1_, byte2_, byte3_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]

    data = bytearray([0x0b, 0xAA, 0x01, 0xFF, 0x1e])
    c = ucPack.crc8(data)
    print(hex(c))

    packeter = ucPack(buffer_size=10, start_index=ord('S'), end_index=ord('E'))
    packeter.buffer.push(ord('S'))
    packeter.buffer.push(5)
    packeter.buffer.push(0x0b)
    packeter.buffer.push(0xAA)
    packeter.buffer.push(0x01)
    packeter.buffer.push(0xFF)
    packeter.buffer.push(0x1e)
    packeter.buffer.push(ord('E'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC1F())

    code_, num_ = packeter.unpacketC1F()

    packeter.packetC1F(code_, num_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]

    data = bytearray([0x0b, 0xAA, 0x01, 0xFF, 0x1e, 0x32, 0x11, 0x00, 0xda])
    c = ucPack.crc8(data)
    print(hex(c))

    packeter = ucPack(buffer_size=20, start_index=ord('S'), end_index=ord('E'))
    packeter.buffer.push(ord('S'))
    packeter.buffer.push(9)
    for d in data:
        packeter.buffer.push(d)
    packeter.buffer.push(ord('E'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC2F())

    code_, num1_, num2_ = packeter.unpacketC2F()

    packeter.packetC2F(code_, num1_, num2_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]

    data = bytearray([0x0b,
                      0xAA, 0x01, 0xFF, 0x1e,
                      0x32, 0x11, 0x00, 0xda,
                      0xcc, 0xa0, 0xf2, 0x01,
                      0x00, 0x01, 0xa9, 0x12])
    c = ucPack.crc8(data)
    print(hex(c))

    packeter = ucPack(buffer_size=30, start_index=ord('S'), end_index=ord('E'))
    packeter.buffer.push(ord('S'))
    packeter.buffer.push(17)
    for d in data:
        packeter.buffer.push(d)
    packeter.buffer.push(ord('E'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC4F())

    code_, num1_, num2_, num3_, num4_ = packeter.unpacketC4F()

    packeter.packetC4F(code_, num1_, num2_, num3_, num4_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]

    data = bytearray([0x0b,
                      0xAA, 0x01, 0xFF, 0x1e,
                      0x32, 0x11, 0x00, 0xda,
                      0xcc, 0xa0, 0xf2, 0x01,
                      0x00, 0x01, 0xa9, 0x12,
                      0xAb, 0xb1, 0x0F, 0xae,
                      0x12, 0xd1, 0xd0, 0xaa,
                      0xc1, 0xa4, 0xf6, 0x09,
                      0x00, 0x01, 0xa9, 0x1a,
                      ])
    c = ucPack.crc8(data)
    print(hex(c))

    packeter = ucPack(buffer_size=40, start_index=ord('S'), end_index=ord('E'))
    packeter.buffer.push(ord('S'))
    packeter.buffer.push(33)
    for d in data:
        packeter.buffer.push(d)
    packeter.buffer.push(ord('E'))
    packeter.buffer.push(c)

    packeter.checkPayload()

    print(packeter.payload)

    print(packeter.unpacketC8F())

    code_, num1_, num2_, num3_, num4_, num5_, num6_, num7_, num8_ = packeter.unpacketC8F()

    packeter.packetC8F(code_, num1_, num2_, num3_, num4_, num5_, num6_, num7_, num8_)

    print(packeter.msg)

    assert data == packeter.msg[2:2+packeter.msg_size-4]