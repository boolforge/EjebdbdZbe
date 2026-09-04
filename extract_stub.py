#!/usr/bin/env python3
import sys, os

def extract(axe_path, stub_bin_path, stub_h_path):
    with open(axe_path, 'rb') as f:
        data = f.read()
    if data[:2] != b'MZ':
        print("Error: Not MZ executable")
        return False
    import struct
    e_cparhdr = struct.unpack_from('<H', data, 0x0E)[0]
    header_size = e_cparhdr * 16
    print(f"Header size: {header_size} bytes")
    stub_offset = header_size
    stub_size = 0x434
    if stub_offset + stub_size > len(data):
        print("Error: File too small")
        return False
    stub_data = data[stub_offset:stub_offset + stub_size]
    os.makedirs(os.path.dirname(stub_bin_path), exist_ok=True)
    with open(stub_bin_path, 'wb') as f:
        f.write(stub_data)
    print(f"Wrote {len(stub_data)} bytes to {stub_bin_path}")
    os.makedirs(os.path.dirname(stub_h_path), exist_ok=True)
    with open(stub_h_path, 'w') as f:
        f.write('// Auto-generated
static const uint8_t axe_stub[0x434] = {
')
        for i in range(0, len(stub_data), 16):
            chunk = stub_data[i:i+16]
            f.write('    ' + ', '.join(f'0x{b:02x}' for b in chunk) + ',
')
        f.write('};
')
    print(f"Wrote C header to {stub_h_path}")
    return True

if __name__ == '__main__':
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <axe.exe> <stub.bin> <stub.h>")
        sys.exit(1)
    success = extract(sys.argv[1], sys.argv[2], sys.argv[3])
    sys.exit(0 if success else 1)
