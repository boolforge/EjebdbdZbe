
#!/usr/bin/env python3
"""
SEA AXE 2.2 - Empirical Verification Script

This script:
1. Downloads test files from boolforge/EjebdbdZbe repository
2. Handles compressed archives (ZIP, 7z)
3. Runs emu8086_fixed.py emulator against each packed EXE
4. Compares output byte-by-byte with reference unpacked files
5. Generates final verification report

Usage:
    python3 test_axe_verification_en.py

Requirements:
    - Python 3
    - Internet access (to download from GitHub)
    - emu8086_fixed.py in same directory
    - For 7z files: '7z' command line tool (optional)
    - For zip files: built-in zipfile module (standard)
"""

import sys
import os
import subprocess
import hashlib
import urllib.request
import tempfile
import shutil
import zipfile

# ========================================================================
# CONFIGURATION
# ========================================================================

REPO_URL = "https://github.com/boolforge/EjebdbdZbe/raw/main"

# Files to download (packed EXEs and their unpacked references)
# Format: (packed_name, unpacked_name, expected_sha1)
TEST_FILES = [
    ("INSTALL.EXE", "INSTALL_unpacked.EXE", "fd8db948b995467120677414defce1dd9e8b3194"),
    ("EDGE.EXE", "EDGE_unpacked.EXE", "2bdb85db53ab7a4b66cd0ef228c831c1c5887bcd"),
    ("SETUP.EXE", "SETUP_unpacked.EXE", "34c667bf00422290f4cc6fcb91a6d1643d340495"),
    ("HILLSFAR_MAIN.EXE", "HILLSFAR_MAIN_unpacked.EXE", "114d927c8bf03ed61b66d430248f244ca733738c"),
]

# Compressed archives containing packed EXEs
COMPRESSED_ARCHIVES = [
    "Circuit-s-Edge_DOS_EN_Floppy.zip",
    "002685_circuits_edge.7z",
]

# Temporary directory
TEMP_DIR = tempfile.mkdtemp(prefix="axe_verify_")
EXTRACT_DIR = os.path.join(TEMP_DIR, "extracted")

# ========================================================================
# DOWNLOAD FUNCTIONS
# ========================================================================

def download_file(url, destination):
    """Download a file from GitHub"""
    try:
        print(f"  Downloading {os.path.basename(destination)}...", end=" ")
        with urllib.request.urlopen(url) as response:
            data = response.read()
        with open(destination, 'wb') as f:
            f.write(data)
        size = len(data)
        print(f"OK ({size:,} bytes)")
        return True, size
    except Exception as e:
        print(f"FAIL: {e}")
        return False, 0

# ========================================================================
# EXTRACTION FUNCTIONS
# ========================================================================

def extract_zip(zip_path, extract_to):
    """Extract ZIP archive"""
    try:
        print(f"  Extracting {os.path.basename(zip_path)}...", end=" ")
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_to)
        extracted = zip_ref.namelist()
        print(f"OK ({len(extracted)} files)")
        return True, extracted
    except Exception as e:
        print(f"FAIL: {e}")
        return False, []

def extract_7z(sevenz_path, extract_to):
    """Extract 7z archive using 7z command line tool"""
    try:
        print(f"  Extracting {os.path.basename(sevenz_path)}...", end=" ")
        result = subprocess.run(
            ['7z', 'x', sevenz_path, f'-o{extract_to}', '-y'],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            print("OK")
            return True
        else:
            print(f"FAIL (code {result.returncode})")
            return False
    except FileNotFoundError:
        print("FAIL: '7z' command not found. Install p7zip-full.")
        return False
    except Exception as e:
        print(f"FAIL: {e}")
        return False

def find_exe_files(directory):
    """Find all EXE files in a directory tree"""
    exe_files = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.upper().endswith(('.EXE', '.COM')):
                full_path = os.path.join(root, file)
                exe_files.append(full_path)
    return exe_files

# ========================================================================
# VERIFICATION FUNCTIONS
# ========================================================================

def calculate_sha1(filepath):
    """Calculate SHA1 of a file"""
    sha1 = hashlib.sha1()
    with open(filepath, 'rb') as f:
        while True:
            data = f.read(65536)
            if not data:
                break
            sha1.update(data)
    return sha1.hexdigest()

def compare_files(file1, file2):
    """Compare two files byte by byte"""
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        data1 = f1.read()
        data2 = f2.read()
    
    if data1 == data2:
        return True, 0, 0
    
    # Find first difference
    min_len = min(len(data1), len(data2))
    for i in range(min_len):
        if data1[i] != data2[i]:
            return False, i, min_len
    
    # Different length
    return False, min_len, max(len(data1), len(data2))

def run_emulator(packed_file, output_file):
    """Run the corrected emulator"""
    emulator = "./emu8086_fixed.py"
    if not os.path.exists(emulator):
        print(f"  ERROR: {emulator} not found")
        return False
    
    cmd = [sys.executable, emulator, packed_file, output_file]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            print(f"  Emulator executed successfully")
            return True
        else:
            print(f"  ERROR: Emulator failed (code {result.returncode})")
            if result.stderr:
                print(f"  STDERR: {result.stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        print(f"  ERROR: Emulator timeout")
        return False
    except Exception as e:
        print(f"  ERROR: {e}")
        return False

# ========================================================================
# MAIN FUNCTION
# ========================================================================

def main():
    print("=" * 70)
    print("SEA AXE 2.2 - EMPIRICAL VERIFICATION SCRIPT")
    print("=" * 70)
    print()
    
    # Create directories
    os.makedirs(TEMP_DIR, exist_ok=True)
    os.makedirs(EXTRACT_DIR, exist_ok=True)
    print(f"Temporary directory: {TEMP_DIR}")
    print()
    
    # ================================================================
    # PHASE 1: DOWNLOAD DIRECT TEST FILES
    # ================================================================
    print("[" + "=" * 60 + "]")
    print("PHASE 1: DOWNLOADING DIRECT TEST FILES")
    print("=" * 60 + "]")
    print()
    
    direct_files = {}
    for packed_name, unpacked_name, _ in TEST_FILES:
        # Download packed
        packed_url = f"{REPO_URL}/{packed_name}"
        packed_path = os.path.join(TEMP_DIR, packed_name)
        success, _ = download_file(packed_url, packed_path)
        if success:
            direct_files[packed_name] = packed_path
        
        # Download unpacked
        unpacked_url = f"{REPO_URL}/{unpacked_name}"
        unpacked_path = os.path.join(TEMP_DIR, unpacked_name)
        success, _ = download_file(unpacked_url, unpacked_path)
        if success:
            direct_files[unpacked_name] = unpacked_path
    
    print()
    
    # ================================================================
    # PHASE 2: DOWNLOAD AND EXTRACT COMPRESSED ARCHIVES
    # ================================================================
    print("[" + "=" * 60 + "]")
    print("PHASE 2: DOWNLOADING AND EXTRACTING COMPRESSED ARCHIVES")
    print("=" * 60 + "]")
    print()
    
    archive_files = {}
    for archive_name in COMPRESSED_ARCHIVES:
        archive_url = f"{REPO_URL}/{archive_name}"
        archive_path = os.path.join(TEMP_DIR, archive_name)
        
        success, size = download_file(archive_url, archive_path)
        if not success:
            print(f"  WARNING: Could not download {archive_name}")
            continue
        
        # Extract based on file extension
        if archive_name.endswith('.zip'):
            success, extracted = extract_zip(archive_path, EXTRACT_DIR)
            if success:
                archive_files[archive_name] = extracted
        elif archive_name.endswith('.7z'):
            success = extract_7z(archive_path, EXTRACT_DIR)
            if success:
                archive_files[archive_name] = find_exe_files(EXTRACT_DIR)
        
        # Find EXE files in extracted directory
        exe_files = find_exe_files(EXTRACT_DIR)
        if exe_files:
            print(f"  Found {len(exe_files)} EXE files in {archive_name}")
            for exe in exe_files:
                print(f"    - {os.path.basename(exe)}")
    
    print()
    
    # ================================================================
    # PHASE 3: COLLECT ALL PACKED FILES
    # ================================================================
    print("[" + "=" * 60 + "]")
    print("PHASE 3: COLLECTING ALL PACKED FILES")
    print("=" * 60 + "]")
    print()
    
    # Collect all packed files (from direct downloads and archives)
    all_packed = []
    
    # From direct downloads
    for packed_name in direct_files:
        if packed_name.endswith('.EXE') and not packed_name.endswith('_unpacked.EXE'):
            all_packed.append(direct_files[packed_name])
            print(f"  Direct: {packed_name}")
    
    # From extracted archives
    for archive_name, extracted in archive_files.items():
        for file_path in extracted:
            if os.path.isfile(file_path) and file_path.upper().endswith('.EXE'):
                # Skip unpacked files
                if '_unpacked' not in file_path.upper():
                    all_packed.append(file_path)
                    print(f"  From {archive_name}: {os.path.basename(file_path)}")
    
    print(f"\nTotal packed files found: {len(all_packed)}")
    print()
    
    if not all_packed:
        print("ERROR: No packed files found!")
        print("Please check:")
        print("  1. Internet connection")
        print("  2. GitHub accessibility")
        print("  3. 7z command line tool (for .7z files)")
        return
    
    # ================================================================
    # PHASE 4: SHA1 VERIFICATION
    # ================================================================
    print("[" + "=" * 60 + "]")
    print("PHASE 4: SHA1 INTEGRITY VERIFICATION")
    print("=" * 60 + "]")
    print()
    
    sha1_results = {}
    for packed_name, unpacked_name, expected_sha in TEST_FILES:
        unpacked_path = os.path.join(TEMP_DIR, unpacked_name)
        if os.path.exists(unpacked_path):
            actual_sha = calculate_sha1(unpacked_path)
            sha1_results[unpacked_name] = (actual_sha, expected_sha)
            status = "OK" if actual_sha == expected_sha else "MISMATCH"
            print(f"  {unpacked_name}: {status}")
            print(f"    Expected: {expected_sha}")
            print(f"    Actual:   {actual_sha}")
        else:
            print(f"  {unpacked_name}: NOT DOWNLOADED")
    
    print()
    
    # ================================================================
    # PHASE 5: RUN EMULATOR
    # ================================================================
    print("[" + "=" * 60 + "]")
    print("PHASE 5: RUNNING CORRECTED EMULATOR")
    print("=" * 60 + "]")
    print()
    
    emulator_results = {}
    
    # For each packed file, find its unpacked reference
    for packed_path in all_packed:
        packed_name = os.path.basename(packed_path)
        
        # Try to find matching unpacked file
        unpacked_path = None
        for pn, un, _ in TEST_FILES:
            if pn.upper() == packed_name.upper():
                unpacked_path = os.path.join(TEMP_DIR, un)
                break
        
        if not unpacked_path or not os.path.exists(unpacked_path):
            # Try to find in extracted directory
            base_name = os.path.splitext(packed_name)[0]
            unpacked_name = f"{base_name}_unpacked.EXE"
            unpacked_path = os.path.join(EXTRACT_DIR, unpacked_name)
            if not os.path.exists(unpacked_path):
                unpacked_path = os.path.join(TEMP_DIR, unpacked_name)
        
        if not unpacked_path or not os.path.exists(unpacked_path):
            print(f"  {packed_name}: No reference file found, skipping...")
            continue
        
        output_path = os.path.join(TEMP_DIR, f"out_{packed_name}")
        
        print(f"  Processing {packed_name}...")
        if run_emulator(packed_path, output_path):
            if os.path.exists(output_path):
                is_match, diff_offset, diff_len = compare_files(output_path, unpacked_path)
                emulator_results[packed_name] = {
                    'output': output_path,
                    'reference': unpacked_path,
                    'match': is_match,
                    'diff_offset': diff_offset,
                    'diff_len': diff_len
                }
                if is_match:
                    print(f"    ✅ BYTE-EXACT MATCH")
                else:
                    print(f"    ❌ MISMATCH at offset {diff_offset} (length {diff_len})")
            else:
                print(f"    ❌ No output generated")
        else:
            print(f"    ❌ Emulator failed")
    
    print()
    
    # ================================================================
    # PHASE 6: FINAL REPORT
    # ================================================================
    print("[" + "=" * 60 + "]")
    print("PHASE 6: FINAL REPORT")
    print("=" * 60 + "]")
    print()
    
    # SHA1 Summary
    print("SHA1 VERIFICATION:")
    all_sha_ok = True
    for unpacked_name, (actual, expected) in sha1_results.items():
        status = "✅" if actual == expected else "❌"
        print(f"  {status} {unpacked_name}: {actual}")
        if actual != expected:
            all_sha_ok = False
    print()
    
    # Emulator Summary
    print("EMULATOR VERIFICATION:")
    all_emulator_ok = True
    for packed_name, result in emulator_results.items():
        status = "✅" if result['match'] else "❌"
        print(f"  {status} {packed_name}")
        if not result['match']:
            print(f"      Difference at offset {result['diff_offset']}")
            all_emulator_ok = False
    print()
    
    # Conclusion
    print("CONCLUSION:")
    if all_sha_ok and all_emulator_ok and emulator_results:
        print("  ✅✅✅ ALL TESTS PASSED ✅✅✅")
        print("  The corrected emulator produces byte-exact output.")
        print("  The algorithm is VERIFIED.")
        print()
        print("  Next step: Create C implementation of the verified algorithm")
    elif all_sha_ok and emulator_results:
        print("  ⚠️  Files downloaded correctly, but emulator failed.")
        print("  Check emulator implementation or file formats.")
    else:
        print("  ❌ Cannot conclude. Issues detected.")
        print("  Check download connectivity and file availability.")
    
    print()
    print("=" * 70)
    print(f"Temporary files in: {TEMP_DIR}")
    print("DO NOT delete until manual verification if needed.")
    print("=" * 70)

if __name__ == "__main__":
    main()