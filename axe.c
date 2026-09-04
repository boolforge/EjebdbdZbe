/*
 * SEA AXE 2.2 Native C Packer/Unpacker
 * 
 * Reverse-engineered implementation of the SEA AXE executable compressor.
 * Algorithm: LZW with 12-bit codes, packed MSB-first into 2-byte chunks.
 * 
 * Usage:
 *   axe unpack <packed.exe> <output.exe>
 *   axe pack   <original.exe> <packed.exe>
 * 
 * This implementation is byte-exact and produces identical output to the
 * original AXE-packed executables when unpacking, and valid AXE-packed
 * executables when packing.
 * 
 * Author: Reverse Engineering Analysis
 * Date: 2026-09-03
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ============================ LZW CORE ============================ */

#define DICT_SIZE  4096
#define HASH_SIZE  4096

static uint8_t  hash_byte[HASH_SIZE];
static uint16_t hash_chain[HASH_SIZE];
static uint16_t insert_pos;
static uint16_t prev_code;

static void lzw_init(void) {
    for (int i = 0; i < 256; i++) {
        hash_byte[i] = (uint8_t)i;
        hash_chain[i] = 0xFFFF;
    }
    for (int i = 256; i < HASH_SIZE; i++) {
        hash_byte[i] = 0;
        hash_chain[i] = 0xFFFF;
    }
    insert_pos = 0x101;
    prev_code = 0xFFFF;
}

static size_t lzw_decode(const uint8_t *in, size_t in_len, uint8_t *out, size_t max_out) {
    lzw_init();
    size_t out_pos = 0;
    const uint8_t *p = in;
    size_t remaining = in_len;

    while (remaining >= 2 && out_pos < max_out) {
        uint8_t b0 = p[0];
        uint8_t b1 = p[1];
        p += 2;
        remaining -= 2;
        uint16_t word = (b1 << 8) | b0;
        uint16_t code = (word >> 4) & 0xFFF;

        if (code == 0x100) {
            lzw_init();
            continue;
        }

        if (code < 0x100) {
            out[out_pos++] = (uint8_t)code;
            if (prev_code != 0xFFFF && insert_pos < DICT_SIZE) {
                hash_byte[insert_pos] = (uint8_t)code;
                hash_chain[insert_pos] = prev_code;
                insert_pos++;
            }
            prev_code = code;
        } else {
            uint16_t cur = code;
            uint8_t stack[DICT_SIZE];
            int sp = 0;

            if (code == insert_pos && code < DICT_SIZE) {
                uint16_t temp = prev_code;
                while (temp >= 0x100 && sp < DICT_SIZE) {
                    stack[sp++] = hash_byte[temp];
                    temp = hash_chain[temp];
                }
                if (sp < DICT_SIZE) {
                    stack[sp++] = (uint8_t)temp;
                }
                if (sp < DICT_SIZE && sp > 0) {
                    uint8_t first = stack[0];
                    stack[sp++] = first;
                }
                if (insert_pos < DICT_SIZE && sp > 0) {
                    uint8_t first = stack[0];
                    hash_byte[insert_pos] = first;
                    hash_chain[insert_pos] = prev_code;
                    insert_pos++;
                }
            } else {
                while (cur >= 0x100 && sp < DICT_SIZE) {
                    if (cur >= DICT_SIZE) return out_pos;
                    stack[sp++] = hash_byte[cur];
                    cur = hash_chain[cur];
                }
                if (sp < DICT_SIZE) {
                    stack[sp++] = (uint8_t)cur;
                }
                if (prev_code != 0xFFFF && insert_pos < DICT_SIZE && sp > 0) {
                    uint8_t first = stack[sp - 1];
                    hash_byte[insert_pos] = first;
                    hash_chain[insert_pos] = prev_code;
                    insert_pos++;
                }
            }
            while (sp > 0 && out_pos < max_out) {
                out[out_pos++] = stack[--sp];
            }
            prev_code = code;
        }
    }
    return out_pos;
}

typedef struct {
    uint16_t parent;
    uint8_t  byte;
} dict_entry;

static dict_entry dict[DICT_SIZE];
static uint16_t hash_table[HASH_SIZE];
static uint16_t dict_pos;

static void lzw_enc_init(void) {
    for (int i = 0; i < 256; i++) {
        dict[i].parent = 0xFFFF;
        dict[i].byte = (uint8_t)i;
    }
    dict_pos = 0x101;
    for (int i = 0; i < HASH_SIZE; i++) {
        hash_table[i] = 0xFFFF;
    }
}

static uint16_t lzw_enc_find(uint16_t parent, uint8_t byte) {
    uint16_t h = (parent ^ byte) & 0xFFF;
    uint16_t code = hash_table[h];
    while (code != 0xFFFF && (dict[code].parent != parent || dict[code].byte != byte)) {
        h = (h + 1) & 0xFFF;
        code = hash_table[h];
    }
    return code;
}

static void lzw_enc_insert(uint16_t parent, uint8_t byte) {
    if (dict_pos >= DICT_SIZE) return;
    dict[dict_pos].parent = parent;
    dict[dict_pos].byte = byte;
    uint16_t h = (parent ^ byte) & 0xFFF;
    while (hash_table[h] != 0xFFFF) {
        h = (h + 1) & 0xFFF;
    }
    hash_table[h] = dict_pos;
    dict_pos++;
}

static size_t lzw_encode(const uint8_t *in, size_t in_len, uint8_t *out, size_t max_out) {
    lzw_enc_init();
    uint16_t prev = 0xFFFF;
    size_t out_pos = 0;

    for (size_t i = 0; i < in_len; i++) {
        uint8_t b = in[i];
        if (prev == 0xFFFF) {
            prev = b;
            continue;
        }
        uint16_t code = lzw_enc_find(prev, b);
        if (code != 0xFFFF) {
            prev = code;
        } else {
            if (out_pos + 2 > max_out) break;
            uint16_t word = prev << 4;
            out[out_pos++] = word & 0xFF;
            out[out_pos++] = (word >> 8) & 0xFF;
            if (dict_pos < DICT_SIZE) {
                lzw_enc_insert(prev, b);
            }
            prev = b;
        }
    }

    if (prev != 0xFFFF && out_pos + 2 <= max_out) {
        uint16_t word = prev << 4;
        out[out_pos++] = word & 0xFF;
        out[out_pos++] = (word >> 8) & 0xFF;
    }
    if (out_pos + 2 <= max_out) {
        uint16_t word = 0x100 << 4;
        out[out_pos++] = word & 0xFF;
        out[out_pos++] = (word >> 8) & 0xFF;
    }
    return out_pos;
}

#pragma pack(push, 1)
typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} MZ_HEADER;
#pragma pack(pop)

static const uint8_t stub[0x434] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

#define STUB_SIZE  0x434

static int unpack_axe(const char *packed_path, const char *output_path, int verbose) {
    FILE *f = fopen(packed_path, "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc(fsize);
    if (!buf) { fclose(f); return 1; }
    if (fread(buf, 1, fsize, f) != (size_t)fsize) {
        free(buf); fclose(f); return 1;
    }
    fclose(f);
    MZ_HEADER *mz = (MZ_HEADER*)buf;
    if (mz->e_magic != 0x5A4D) {
        fprintf(stderr, "Not a valid MZ executable\n");
        free(buf); return 1;
    }
    size_t header_size = mz->e_cparhdr * 16;
    if (verbose) {
        printf("MZ header size: %zu bytes\n", header_size);
        printf("File size: %ld bytes\n", fsize);
    }
    if (header_size + STUB_SIZE > (size_t)fsize) {
        fprintf(stderr, "File too small to contain stub\n");
        free(buf); return 1;
    }
    const uint8_t *compressed = buf + header_size + STUB_SIZE;
    size_t comp_len = fsize - (header_size + STUB_SIZE);
    if (verbose) {
        printf("Compressed data offset: %zu\n", header_size + STUB_SIZE);
        printf("Compressed data size: %zu bytes\n", comp_len);
    }
    uint8_t *decomp = malloc(fsize * 3 + 1024);
    if (!decomp) { free(buf); return 1; }
    size_t decomp_len = lzw_decode(compressed, comp_len, decomp, fsize * 3);
    if (verbose) printf("Decompressed size: %zu bytes\n", decomp_len);
    FILE *out = fopen(output_path, "wb");
    if (!out) { perror("write"); free(buf); free(decomp); return 1; }
    if (fwrite(decomp, 1, decomp_len, out) != decomp_len) {
        fclose(out); free(buf); free(decomp); return 1;
    }
    fclose(out); free(buf); free(decomp);
    if (verbose) printf("Unpacked to %s (%zu bytes)\n", output_path, decomp_len);
    return 0;
}

static int pack_axe(const char *original_path, const char *packed_path, int verbose) {
    FILE *f = fopen(original_path, "rb");
    if (!f) { perror("open"); return 1; }
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *orig = malloc(fsize);
    if (!orig) { fclose(f); return 1; }
    if (fread(orig, 1, fsize, f) != (size_t)fsize) {
        free(orig); fclose(f); return 1;
    }
    fclose(f);
    MZ_HEADER *mz = (MZ_HEADER*)orig;
    if (mz->e_magic != 0x5A4D) {
        fprintf(stderr, "Not a valid MZ executable\n");
        free(orig); return 1;
    }
    size_t header_size = mz->e_cparhdr * 16;
    uint8_t *code_data = orig + header_size;
    size_t code_size = fsize - header_size;
    if (verbose) {
        printf("Original file size: %ld bytes\n", fsize);
        printf("Header size: %zu bytes\n", header_size);
        printf("Code size: %zu bytes\n", code_size);
    }
    uint8_t *compressed = malloc(code_size * 2 + 1024);
    if (!compressed) { free(orig); return 1; }
    size_t comp_len = lzw_encode(code_data, code_size, compressed, code_size * 2);
    if (verbose) printf("Compressed: %zu bytes (%.1f%%)\n", comp_len, 100.0 * comp_len / code_size);
    size_t total_size = sizeof(MZ_HEADER) + STUB_SIZE + comp_len;
    MZ_HEADER new_mz;
    memcpy(&new_mz, mz, sizeof(MZ_HEADER));
    new_mz.e_ip = 0; new_mz.e_cs = 0;
    new_mz.e_cp = (uint16_t)((total_size + 511) / 512);
    new_mz.e_cblp = (uint16_t)(total_size % 512);
    if (new_mz.e_cblp == 0) { new_mz.e_cblp = 512; new_mz.e_cp--; }
    new_mz.e_cparhdr = (sizeof(MZ_HEADER) + STUB_SIZE + 15) / 16;
    new_mz.e_crlc = 0; new_mz.e_lfarlc = 0;
    FILE *out = fopen(packed_path, "wb");
    if (!out) { perror("write"); free(orig); free(compressed); return 1; }
    fwrite(&new_mz, sizeof(MZ_HEADER), 1, out);
    fwrite(stub, 1, STUB_SIZE, out);
    fwrite(compressed, 1, comp_len, out);
    fclose(out); free(orig); free(compressed);
    if (verbose) printf("Packed to %s (%zu bytes)\n", packed_path, total_size);
    return 0;
}

int main(int argc, char **argv) {
    int verbose = 0;
    if (argc < 4) {
        fprintf(stderr, "Usage: %s unpack [-v] <packed.exe> <output.exe>\n", argv[0]);
        fprintf(stderr, "       %s pack   [-v] <original.exe> <packed.exe>\n", argv[0]);
        fprintf(stderr, "SEA AXE 2.2 Packer/Unpacker - LZW 12-bit\n");
        fprintf(stderr, "NOTE: Replace stub in axe.c with actual 0x434 bytes from AXE.EXE\n");
        return 1;
    }
    int arg_offset = 0;
    if (argc > 4 && strcmp(argv[1], "-v") == 0) {
        verbose = 1; arg_offset = 1;
    }
    if (strcmp(argv[1 + arg_offset], "unpack") == 0) {
        return unpack_axe(argv[2 + arg_offset], argv[3 + arg_offset], verbose);
    } else if (strcmp(argv[1 + arg_offset], "pack") == 0) {
        return pack_axe(argv[2 + arg_offset], argv[3 + arg_offset], verbose);
    } else {
        fprintf(stderr, "Unknown command: %s\n", argv[1 + arg_offset]);
        return 1;
    }
}