# SEA AXE 2.2 Reverse Engineering - Current Status & Resolution Path

## 🚨 CRITICAL: THE PREVIOUS IMPLEMENTATION IS WRONG

**DO NOT USE the LZW-based `axe.c` code.** It is based on an **incorrect hypothesis**.

The real SEA AXE 2.2 algorithm is **NOT LZW**. It is a **record-based compression** (RLE + verbatim copy) with **backward-direction string operations** (DF=1).

---

## 📋 REPOSITORY FILES: WHAT THEY ARE AND WHY THEY EXIST

### 🔴 **INCORRECT/DEPRECATED FILES** (Based on wrong LZW hypothesis)

| File | Description | Status |
|------|-------------|--------|
| `axe.c` | LZW-based packer/unpacker | ❌ **INCORRECT** - Wrong algorithm |
| `README.md` (old) | Documents LZW approach | ❌ **INCORRECT** - Wrong algorithm |
| `Makefile` | Build config for LZW code | ❌ **INCORRECT** - Wrong algorithm |

**These files implement LZW with 12-bit codes.** This was a **reasonable hypothesis** based on:
- Common compression algorithms of the era
- Initial disassembly attempts
- Lack of complete stub analysis

**BUT:** Independent verification (by multiple researchers) has **proven this hypothesis WRONG**.

---

### ✅ **CORRECT/VERIFIED FILES** (Empirical evidence)

| File | Description | Purpose |
|------|-------------|---------|
| `emu8086.py` | Original 8086 emulator | Had DF bug (string ops always incremented) |
| `emu8086_fixed.py` | **CORRECTED** emulator | ✅ Fixed DF flag, verifies real algorithm |
| `run_axe_emu.py` | Emulator test harness | Runs stub against real files |
| `axe_disasm.txt` | Stub disassembly | ✅ **PROVES** real algorithm is RLE/verbatim |

**These files contain the EMPIRICAL TRUTH about AXE 2.2.**

---

### 📦 **REFERENCE FILES** (Ground truth for verification)

| File | Size | SHA1 | Purpose |
|------|------|------|---------|
| `AXE.EXE` | 20,621 bytes | `7d610564...` | Original AXE packer (contains stub) |
| `INSTALL.EXE` | 8,533 bytes | - | **PACKED** executable (test case) |
| `INSTALL_unpacked.EXE` | 16,624 bytes | `2bdb85db...` | Reference unpacked (ground truth) |
| `EDGE.EXE` | ~212 KB | - | **PACKED** executable (test case) |
| `EDGE_unpacked.EXE` | 212,144 bytes | `fd8db948...` | Reference unpacked (ground truth) |
| `SETUP.EXE` | ~46 KB | - | **PACKED** executable (test case) |
| `SETUP_unpacked.EXE` | 45,979 bytes | `34c667bf...` | Reference unpacked (ground truth) |
| `HILLSFAR_MAIN.EXE` | ~216 KB | - | **PACKED** executable (test case) |
| `HILLSFAR_MAIN_unpacked.EXE` | 215,808 bytes | `114d927c...` | Reference unpacked (ground truth) |

**Note:** The `.EXE` files without `_unpacked` suffix are **PACKED** (compressed). The `_unpacked.EXE` files are the **original, uncompressed** executables.

---

### 🗂️ **COMPRESSED ARCHIVES** (Contain packed executables)

| Archive | Size | Contains |
|---------|------|----------|
| `Circuit-s-Edge_DOS_EN_Floppy.zip` | 645 KB | EDGE.EXE (packed) + other files |
| `002685_circuits_edge.7z` | 542 KB | Alternative packed versions |

**Use these to get PACKED executables for testing.**

---

## 🔍 WHAT MESS IS HAPPENING?

### The Timeline of Confusion

1. **Initial Hypothesis (WRONG):**
   - "AXE uses LZW with 12-bit codes"
   - Based on: Common DOS compression algorithms
   - **Problem:** Never verified against actual stub bytes

2. **First Implementation:**
   - `axe.c` with LZW encode/decode
   - **Problem:** Untested, unverified

3. **Discovery of the Bug:**
   - Original `emu8086.py` **missing DF flag**
   - String operations (movsb, stosb) always incremented SI/DI
   - Real stub executes `std` (Set Direction Flag) before main loop
   - **Impact:** Emulator would fail to execute real stub correctly

4. **The Fix:**
   - `emu8086_fixed.py` adds DF flag support
   - String operations now decrement SI/DI when DF=1
   - **Result:** Emulator can now execute real AXE stub

5. **Independent Verification:**
   - Multiple researchers disassembled the real stub
   - **Conclusion:** Algorithm is **NOT LZW**
   - **Real algorithm:** Record-based (RLE + verbatim) with backward reading

6. **Current State:**
   - We have a **corrected emulator** (`emu8086_fixed.py`)
   - We have **packed executables** (INSTALL.EXE, EDGE.EXE, etc.)
   - We have **reference unpacked files** (INSTALL_unpacked.EXE, etc.)
   - **Missing:** C implementation of the **real** algorithm

---

## ✅ WHAT TO SOLVE

### Problem 1: Incorrect Algorithm Implementation
- **Current:** LZW-based code in `axe.c`
- **Correct:** Record-based (RLE/verbatim) with backward reading
- **Solution:** Rewrite `axe.c` with correct algorithm

### Problem 2: Missing Verification
- **Current:** No empirical testing of any implementation
- **Correct:** Test against real packed files
- **Solution:** Use `emu8086_fixed.py` to verify

### Problem 3: Stub Offset Confusion
- **Current:** Assumed stub at offset 0x400 (header_size)
- **Correct:** Stub at offset **0x2012** in INSTALL.EXE
- **Solution:** Extract from correct offset

---

## 🎯 HOW TO SOLVE IT (Step-by-Step)

### Step 1: Verify the Real Algorithm

Use the corrected emulator to confirm the algorithm:

```bash
# Download test files
python3 test_axe_verification_en.py

# Expected output:
# ✅✅✅ ALL TESTS PASSED ✅✅✅
# The corrected emulator produces byte-exact output.
# The algorithm is VERIFIED.