#!/bin/bash
# Extract the stub from AXE.EXE and generate the C array
STUB_OFFSET=$((0x2012))
STUB_SIZE=$((0x12D))

if [ ! -f "AXE.EXE" ]; then
    echo "ERROR: AXE.EXE not found"
    echo "Download it first from: https://github.com/boolforge/EjebdbdZbe/"
    exit 1
fi

echo "Extracting stub from AXE.EXE (offset=0x${STUB_OFFSET}, size=${STUB_SIZE})..."
dd if=AXE.EXE of=axe_stub.bin bs=1 skip=$STUB_OFFSET count=$STUB_SIZE 2>/dev/null

if [ ! -f "axe_stub.bin" ]; then
    echo "ERROR: Extraction failed. You need 'dd' (coreutils)"
    exit 1
fi

echo "Generating axe_stub.h..."
echo "// STUB extracted from AXE.EXE - DO NOT EDIT" > axe_stub.h
echo "// Run: ./extract_stub.sh to regenerate" >> axe_stub.h
echo "static const uint8_t axe_stub[0x12D] = {" >> axe_stub.h

python3 -c "
with open('axe_stub.bin','rb') as f:
    data = f.read()
    for i in range(0, len(data), 16):
        line = ', '.join(f'0x{b:02x}' for b in data[i:i+16])
        print(f'    {line},')
" >> axe_stub.h

echo "};" >> axe_stub.h
echo "" >> axe_stub.h
echo "// End of stub" >> axe_stub.h

echo "Done! Copy the contents of axe_stub.h to axe.c"
echo "Then compile with: make"