import struct

def validate_ip_checksum(ip_header_bytes: bytes):
    """
    Validates IPv4 header checksum using raw struct math.
    """
    #Standard IP Header is 20 bytes
    if len(ip_header_bytes) != 20:
        return False # Handling options/variable length is more complex, skip for now

    # Unpack as 10 unsigned shorts (16-bit integers)
    # ! = Network Endian, 10H = Ten 16-bit integers
    words = struct.unpack('!10H', ip_header_bytes)

    # Sum all words
    chksum = sum(words)

    # Fold carry bits (The "1s Complement" Math)
    # If sum > 0xFFFF, take the overflow and add it back to the bottom
    while chksum >> 16:
        chksum = (chksum & 0xFFFF) + (chksum >> 16)

    # Validity Check
    # A valid header sums to 0xFFFF (all 1s) in this math
    return chksum == 0xFFFF