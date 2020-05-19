# SPDX-License-Identifier: GPL-2.0+

from bitstream import BitStream

MODE_NONE = 0
MODE_SCHEME1 = 1

def leading_ones(stream):
    count = 0
    while stream.read(bool):
        count += 1

    return count

class SLDC:

    def __init__(self):
        self.buffer = bytearray(1024)
        self.output = bytearray(0)
        self.buffer_offset = 0

    def add_byte(self, b):
        self.buffer[self.buffer_offset] = b
        self.buffer_offset += 1

        if self.buffer_offset >= len(self.buffer):
            self.buffer_offset = 0
            self.output.extend(self.buffer)

    def decode(self, data):
        stream = BitStream(data)
        mode = MODE_NONE

        while True:
            first_bit = stream.read(bool)
            if first_bit:
                ones = leading_ones(stream)

            if mode == MODE_SCHEME1:
                if not first_bit:
                    self.add_byte(ord(stream.read(bytes, 1)))
                    continue
                elif ones < 8:
                    cnt_field = stream.read(BitStream, ones + 1 if ones < 4 else 11 - ones)
                    if ones > 4:
                        cnt_field += (ones - 4) << (12 - ones)

                    cnt = int(str(cnt_field), 2) + (2 << ones)
                    loc = int(str(stream.read(BitStream, 10)), 2)

                    for i in range(loc, loc + cnt):
                        self.add_byte(self.buffer[i % 1024])

                    continue

            if first_bit and ones == 8:
                control = str(stream.read(BitStream, 3))
                if control == '101': # Scheme 1
                    mode = MODE_SCHEME1
                elif control == '100': # End of record (EOR)
                    self.output.extend(self.buffer[:self.buffer_offset])
                    break
                else:
                    raise ValueError("Can't parse SLDC, unsupported control symbol: %s" % (control))
            else:
                raise ValueError("Can't parse SLDC, unknown action")

        return self.output
