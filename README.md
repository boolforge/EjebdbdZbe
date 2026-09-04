# SEA AXE 2.2 Native C Packer/Unpacker

Byte-exact LZW implementation for SEA AXE 2.2 executable compression.

## Algorithm
- LZW with 12-bit codes
- Codes packed MSB-first: (code << 4) in 16-bit words
- Dictionary: 4096 entries (0x00-0xFF literals, 0x100 reset)
- Hash chain for O(1) lookup

## Build
```bash
make
```

## Usage
```bash
# Unpack
./axe unpack packed.exe output.exe

# Pack
./axe pack original.exe packed.exe

# With verbose
./axe unpack -v packed.exe output.exe
./axe pack -v original.exe packed.exe
```

## Stub Requirement
For PACKING to work, replace the placeholder stub in axe.c with the actual 0x434-byte stub from AXE.EXE:
```bash
# Extract stub from AXE.EXE (offset 0x400, length 0x434)
dd if=AXE.EXE of=stub.bin bs=1 skip=$((0x400)) count=$((0x434))

# Generate C array
python3 -c "
with open('stub.bin','rb') as f:
    data = f.read()
    print('static const uint8_t stub[0x434] = {')
    for i in range(0,len(data),16):
        print('    ' + ', '.join(f'0x{b:02x}' for b in data[i:i+16]) + ',')
    print('};')
" > stub_array.txt
```

## Test Files
Reference files in: https://github.com/boolforge/EjebdbdZbe
- EDGE_unpacked.EXE (212,144 bytes)
- INSTALL_unpacked.EXE (16,624 bytes)
- SETUP_unpacked.EXE (45,979 bytes)

## Verification
```bash
# Unpack test
./axe unpack packed.exe /tmp/out.exe
cmp /tmp/out.exe EDGE_unpacked.EXE

# Round-trip test
./axe pack EDGE_unpacked.EXE /tmp/packed.exe
./axe unpack /tmp/packed.exe /tmp/reunpacked.exe
cmp /tmp/reunpacked.exe EDGE_unpacked.EXE
```

## Notes
- Unpacker works WITHOUT stub
- Packer needs stub for executable output
- Algorithm verified against emu8086.py
