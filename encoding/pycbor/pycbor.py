#!/usr/bin/env python3
import struct

##
# Defines the CBOR types
class pycbor_types:
    MAJOR_TYPE_POSITIVE_INT = 0
    MAJOR_TYPE_NEGATIVE_INT = 1
    MAJOR_TYPE_BYTE_STRING  = 2
    MAJOR_TYPE_TEXT_STRING  = 3
    MAJOR_TYPE_ARRAY        = 4
    MAJOR_TYPE_MAP          = 5
    MAJOR_TYPE_TAG          = 6
    MAJOR_TYPE_SIMPLE       = 7

##
# implements pycbor
class pycbor:
    ##
    # Initialize pycbor class
    def __init__(self):
        self.buf = bytearray()
        self.offset = 0

    ##
    # Returns the encoded buffer and the offset
    def get_encode_buf(self): return bytes(self.buf), self.offset

    ##
    # Encodes the type and length
    def _encode_type_and_length(self, major_type, length):
        if length <= 23:
            self.buf.append((major_type << 5) | length)
            self.offset += 1
        elif length <= 255:
            self.buf.append((major_type << 5) | 24)
            self.buf.append(length)
            self.offset += 2
        elif length <= 65535:
            self.buf.append((major_type << 5) | 25)
            self.buf.extend(struct.pack(">H", length))
            self.offset += 3
        elif length <= 4294967295:
            self.buf.append((major_type << 5) | 26)
            self.buf.extend(struct.pack(">I", length))
            self.offset += 5
        else:
            # 64-bit support
            self.buf.append((major_type << 5) | 27)
            self.buf.extend(struct.pack(">Q", length))
            self.offset += 9

    ##
    # Encodes a positive integer
    def encode_uint(self, num):
        self._encode_type_and_length(pycbor_types.MAJOR_TYPE_POSITIVE_INT, num)

    ##
    # Encodes a byte array
    def encode_byte_array(self, data):
        self._encode_type_and_length(pycbor_types.MAJOR_TYPE_BYTE_STRING, len(data))
        self.buf.extend(data)
        self.offset += len(data)

    ##
    # Encodes a string
    def encode_str(self, str_val):
        encoded_str = str_val.encode('utf-8')
        length = len(encoded_str)
        self._encode_type_and_length(pycbor_types.MAJOR_TYPE_TEXT_STRING, length)
        self.buf.extend(encoded_str)
        self.offset += length

    ##
    # Encodes a map
    def encode_map(self, num_elements):
        self._encode_type_and_length(pycbor_types.MAJOR_TYPE_MAP, num_elements)

    ##
    # Encodes the following cbor data:
    # int, list, bytes, bytearray, str
    def encode(self, data):
        if isinstance(data, int):
            self.encode_uint(data)
        elif isinstance(data, (list, bytes, bytearray)):
            self.encode_byte_array(data)
        elif isinstance(data, str):
            self.encode_str(data)

if __name__ == "__main__":
    cbor = pycbor()
    cbor.encode_map(2)
    cbor.encode("123456")
    cbor.encode(5)
    cbor.encode(3)
    cbor.encode([1, 2, 3, 4, 5])
    buf, length = cbor.get_encode_buf()
    print(buf.hex())
