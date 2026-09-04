/*
 * SEA AXE 2.2 Unpacker - CORRECT IMPLEMENTATION
 * Algorithm: RLE/Verbatim with backward reading (DF=1)
 * Stub: offset 0x2012, size 0x12D in AXE.EXE
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic; uint16_t e_cblp; uint16_t e_cp; uint16_t e_crlc;
    uint16_t e_cparhdr; uint16_t e_minalloc; uint16_t e_maxalloc; uint16_t e_ss;
    uint16_t e_sp; uint16_t e_csum; uint16_t e_ip; uint16_t e_cs;
    uint16_t e_lfarlc; uint16_t e_ovno;
} MZ_HEADER;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
    uint16_t orig_ip; uint16_t orig_cs; uint16_t padding1;
    uint16_t stub_copy_length; uint16_t orig_sp; uint16_t orig_ss;
    uint16_t stub_reloc_target; uint16_t unknown;
} AXE_PARAM_BLOCK;
#pragma pack(pop)

/* REEMPLAZA ESTE STUB CON EL REAL DE AXE.EXE */
static const uint8_t axe_stub[0x12D] = {
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,
    0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90,0x90
};

#define AXE_CMD_RLE_FILL 0xB0
#define AXE_CMD_VERBATIM 0xB2
#define AXE_CMD_END_MASK 0x01

int unpack_axe(const char *input_path, const char *output_path, int verbose) {
    FILE *in_file, *out_file;
    MZ_HEADER mz;
    uint8_t *buffer, *compressed_data, *output;
    size_t file_size, compressed_size;
    uint32_t header_size, param_block_offset;
    AXE_PARAM_BLOCK param_block;
    int result = 0;

    in_file = fopen(input_path, "rb");
    if (!in_file) { fprintf(stderr, "Error: Cannot open '%s': %s\n", input_path, strerror(errno)); return 1; }

    fseek(in_file, 0, SEEK_END);
    file_size = ftell(in_file);
    fseek(in_file, 0, SEEK_SET);

    buffer = (uint8_t *)malloc(file_size);
    if (!buffer) { fprintf(stderr, "Error: No memory\n"); fclose(in_file); return 1; }
    if (fread(buffer, 1, file_size, in_file) != file_size) { fprintf(stderr, "Error: Read failed\n"); free(buffer); fclose(in_file); return 1; }
    fclose(in_file);

    if (buffer[0] != 'M' || buffer[1] != 'Z') { fprintf(stderr, "Error: Not MZ executable\n"); free(buffer); return 1; }

    memcpy(&mz, buffer, sizeof(MZ_HEADER));
    header_size = (uint32_t)mz.e_cparhdr * 16;

    if (verbose) printf("MZ: e_cparhdr=0x%04X, e_ip=0x%04X, e_cs=0x%04X, size=%zu\n", mz.e_cparhdr, mz.e_ip, mz.e_cs, file_size);

    param_block_offset = 0x2000;
    if (file_size >= param_block_offset + sizeof(AXE_PARAM_BLOCK)) {
        memcpy(&param_block, buffer + param_block_offset, sizeof(AXE_PARAM_BLOCK));
        if (verbose) printf("Param: ip=0x%04X, cs=0x%04X, stub_len=0x%04X\n", param_block.orig_ip, param_block.orig_cs, param_block.stub_copy_length);
    }

    uint32_t compressed_offset = header_size;
    uint32_t compressed_end = param_block_offset;
    if (compressed_end <= compressed_offset || compressed_end > file_size) compressed_end = file_size;
    compressed_size = compressed_end - compressed_offset;
    compressed_data = buffer + compressed_offset;

    if (verbose) printf("Compressed: offset=0x%08X, size=%zu\n", compressed_offset, compressed_size);

    output = (uint8_t *)malloc(0x100000);
    if (!output) { fprintf(stderr, "Error: No output buffer\n"); free(buffer); return 1; }

    size_t output_pos = 0;
    int pos = compressed_size - 1;

    while (pos >= 0) {
        uint8_t cmd = compressed_data[pos]; pos--;

        if (cmd & AXE_CMD_END_MASK) { if (verbose) printf("End of stream\n"); break; }

        if ((cmd & 0xFE) == AXE_CMD_RLE_FILL) {
            if (pos < 0) { fprintf(stderr, "Error: RLE truncated\n"); result = 1; goto cleanup; }
            uint8_t fill_byte = compressed_data[pos]; pos--;
            if (pos < 1) { fprintf(stderr, "Error: RLE count truncated\n"); result = 1; goto cleanup; }
            uint16_t count = compressed_data[pos] | (compressed_data[pos+1] << 8); pos -= 2;
            if (verbose) printf("RLE: byte=0x%02X, count=%u\n", fill_byte, count);
            while (count--) {
                if (output_pos >= 0x100000) { fprintf(stderr, "Error: Output buffer full\n"); result = 1; goto cleanup; }
                output[output_pos++] = fill_byte;
            }
        }
        else if ((cmd & 0xFE) == AXE_CMD_VERBATIM) {
            if (pos < 1) { fprintf(stderr, "Error: Verbatim truncated\n"); result = 1; goto cleanup; }
            uint16_t count = compressed_data[pos] | (compressed_data[pos+1] << 8); pos -= 2;
            if (pos < count - 1) { fprintf(stderr, "Error: Verbatim data truncated\n"); result = 1; goto cleanup; }
            uint8_t *verbatim_src = compressed_data + pos - count + 1; pos -= count;
            if (verbose) printf("Verbatim: count=%u\n", count);
            while (count--) {
                if (output_pos >= 0x100000) { fprintf(stderr, "Error: Output buffer full\n"); result = 1; goto cleanup; }
                output[output_pos++] = verbatim_src[count];
            }
        }
        else { fprintf(stderr, "Error: Unknown command 0x%02X\n", cmd); result = 1; goto cleanup; }
    }

    for (size_t i = 0; i < output_pos / 2; i++) {
        uint8_t tmp = output[i];
        output[i] = output[output_pos - 1 - i];
        output[output_pos - 1 - i] = tmp;
    }

    out_file = fopen(output_path, "wb");
    if (!out_file) { fprintf(stderr, "Error: Cannot create '%s'\n", output_path); result = 1; goto cleanup; }
    if (fwrite(output, 1, output_pos, out_file) != output_pos) { fprintf(stderr, "Error: Write failed\n"); result = 1; }
    else if (verbose) printf("Unpacked %zu bytes to %s\n", output_pos, output_path);
    fclose(out_file);

cleanup:
    free(output); free(buffer); return result;
}

void print_usage(const char *prog_name) {
    printf("Usage:\n  %s unpack <packed.exe> <output.exe> [-v]\n", prog_name);
}

int main(int argc, char *argv[]) {
    int verbose = 0, result = 0;
    if (argc < 3) { print_usage(argv[0]); return 1; }
    for (int i = 1; i < argc; i++) if (strcmp(argv[i], "-v") == 0) verbose = 1;
    if (strcmp(argv[1], "unpack") == 0 && argc >= 4) result = unpack_axe(argv[2], argv[3], verbose);
    else { print_usage(argv[0]); return 1; }
    return result;
}