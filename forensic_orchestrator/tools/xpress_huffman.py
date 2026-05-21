from __future__ import annotations

import struct

HUFFMAN_TABLE_SIZE = 256
SYMBOL_COUNT = 512
MAX_CODE_BITS = 15
DECODE_TABLE_SIZE = 1 << MAX_CODE_BITS
BLOCK_SIZE = 65536


class XpressHuffmanError(ValueError):
    pass


def decompress_xpress_huffman(data: bytes, expected_size: int) -> bytes:
    output = bytearray()
    position = 0
    while len(output) < expected_size:
        if len(data) - position < HUFFMAN_TABLE_SIZE:
            raise XpressHuffmanError("Missing XPRESS Huffman table.")
        lengths = _read_code_lengths(data[position : position + HUFFMAN_TABLE_SIZE])
        table = _build_decode_table(lengths)
        position += HUFFMAN_TABLE_SIZE
        if len(data) - position < 4:
            raise XpressHuffmanError("Missing XPRESS Huffman bitstream.")

        next_bits = (_read_u16(data, position) << 16) | _read_u16(data, position + 2)
        position += 4
        extra_bits = 16
        block_end = min(len(output) + BLOCK_SIZE, expected_size)

        while len(output) < block_end:
            symbol = table[next_bits >> (32 - MAX_CODE_BITS)]
            bit_length = lengths[symbol]
            if bit_length == 0:
                raise XpressHuffmanError("Invalid zero-length Huffman symbol.")
            next_bits, extra_bits, position = _consume_bits(
                data, position, next_bits, extra_bits, bit_length
            )

            if symbol < 256:
                output.append(symbol)
                continue

            match_symbol = symbol - 256
            match_length = match_symbol & 0xF
            offset_bit_length = match_symbol >> 4
            if match_length == 15:
                match_length = _read_byte(data, position)
                position += 1
                if match_length == 255:
                    match_length = _read_u16(data, position)
                    position += 2
                    if match_length < 15:
                        raise XpressHuffmanError("Invalid XPRESS match length.")
                    match_length -= 15
                match_length += 15
            match_length += 3

            if offset_bit_length:
                match_offset = next_bits >> (32 - offset_bit_length)
                next_bits, extra_bits, position = _consume_bits(
                    data, position, next_bits, extra_bits, offset_bit_length
                )
            else:
                match_offset = 0
            match_offset += 1 << offset_bit_length
            if match_offset <= 0 or match_offset > len(output):
                raise XpressHuffmanError("Invalid XPRESS match offset.")

            for _ in range(match_length):
                if len(output) >= expected_size:
                    break
                output.append(output[len(output) - match_offset])

    return bytes(output)


def _read_code_lengths(table: bytes) -> list[int]:
    lengths: list[int] = []
    for value in table:
        lengths.append(value & 0x0F)
        lengths.append(value >> 4)
    return lengths


def _build_decode_table(lengths: list[int]) -> list[int]:
    decode = [0] * DECODE_TABLE_SIZE
    entry = 0
    for bit_length in range(1, MAX_CODE_BITS + 1):
        repeat = 1 << (MAX_CODE_BITS - bit_length)
        for symbol, symbol_length in enumerate(lengths):
            if symbol_length != bit_length:
                continue
            if entry + repeat > DECODE_TABLE_SIZE:
                raise XpressHuffmanError("Invalid XPRESS Huffman table.")
            for index in range(repeat):
                decode[entry + index] = symbol
            entry += repeat
    if entry != DECODE_TABLE_SIZE:
        raise XpressHuffmanError("Incomplete XPRESS Huffman table.")
    return decode


def _consume_bits(
    data: bytes,
    position: int,
    next_bits: int,
    extra_bits: int,
    bit_count: int,
) -> tuple[int, int, int]:
    next_bits = (next_bits << bit_count) & 0xFFFFFFFF
    extra_bits -= bit_count
    if extra_bits < 0:
        if position + 2 > len(data):
            raise XpressHuffmanError("XPRESS bitstream ended unexpectedly.")
        next_bits |= (_read_u16(data, position) << (-extra_bits)) & 0xFFFFFFFF
        extra_bits += 16
        position += 2
    return next_bits, extra_bits, position


def _read_u16(data: bytes, position: int) -> int:
    if position + 2 > len(data):
        raise XpressHuffmanError("Unexpected end of XPRESS data.")
    return struct.unpack_from("<H", data, position)[0]


def _read_byte(data: bytes, position: int) -> int:
    if position >= len(data):
        raise XpressHuffmanError("Unexpected end of XPRESS data.")
    return data[position]
