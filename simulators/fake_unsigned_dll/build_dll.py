"""
GhostHunt — Demo C: Pure-Python Synthesizer of Harmless Unsigned 64-bit PE DLL
Authoritative module specified in DEVELOPMENT_ROADMAP.md (Version 1.4.3).

Architectural Goal:
Generates a syntactically valid, minimal 64-bit PE DLL in pure Python without
requiring MSVC, Clang, GCC, or external compilers.

Safety Guarantees:
1. Purely academic test binary containing a harmless DllMain stub (returns 1).
2. Contains zero malicious functionality, zero network capability, zero payload.
3. Has NO embedded signature (IMAGE_DIRECTORY_ENTRY_SECURITY size = 0).
4. Strictly used for evaluating WinVerifyTrust and GhostHunt Signal 3 detection.
"""

import os
import struct
import sys
from typing import Optional


def build_unsigned_pe_dll(output_path: Optional[str] = None) -> bytes:
    """
    Synthesizes a minimal valid 64-bit (PE32+) Windows DLL.
    If output_path is provided, writes the binary to disk.
    Returns the binary bytes.
    """
    # ---------------------------------------------------------
    # 1. MS-DOS Header (64 bytes)
    # ---------------------------------------------------------
    dos_header = bytearray(64)
    dos_header[0:2] = b"MZ"  # e_magic
    struct.pack_into("<H", dos_header, 0x02, 0x0090)  # e_cblp
    struct.pack_into("<H", dos_header, 0x04, 0x0003)  # e_cp
    struct.pack_into("<H", dos_header, 0x3C, 0x0080)  # e_lfanew: PE header offset (128)

    # DOS stub (64 bytes from 0x40 to 0x80)
    dos_stub = b"\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21\xb8\x01\x4c\xcd\x21"
    dos_stub += b"This program cannot be run in DOS mode.\r\r\n$"
    dos_stub += b"\x00" * (64 - len(dos_stub))

    # ---------------------------------------------------------
    # 2. PE Signature (4 bytes at offset 0x80)
    # ---------------------------------------------------------
    pe_sig = b"PE\x00\x00"

    # ---------------------------------------------------------
    # 3. COFF File Header (20 bytes)
    # ---------------------------------------------------------
    machine = 0x8664  # IMAGE_FILE_MACHINE_AMD64 (x64)
    number_of_sections = 1
    time_date_stamp = 0x66000000
    ptr_to_symbol_table = 0
    number_of_symbols = 0
    size_of_optional_header = 240  # PE32+ optional header size
    # Characteristics: EXECUTABLE_IMAGE (0x0002) | LARGE_ADDRESS_AWARE (0x0020) | DLL (0x2000)
    characteristics = 0x2022

    coff_header = struct.pack(
        "<HHIIIHH",
        machine,
        number_of_sections,
        time_date_stamp,
        ptr_to_symbol_table,
        number_of_symbols,
        size_of_optional_header,
        characteristics,
    )

    # ---------------------------------------------------------
    # 4. Optional Header (PE32+ / 64-bit, 240 bytes)
    # ---------------------------------------------------------
    magic = 0x020B  # PE32+
    major_linker_version = 14
    minor_linker_version = 0
    size_of_code = 0x0200
    size_of_init_data = 0
    size_of_uninit_data = 0
    entry_point_rva = 0x1000  # Points into .text section
    base_of_code = 0x1000
    image_base = 0x180000000  # 64-bit default base
    section_alignment = 0x1000
    file_alignment = 0x0200
    major_os_version = 6
    minor_os_version = 0
    major_image_version = 0
    minor_image_version = 0
    major_subsystem_version = 6
    minor_subsystem_version = 0
    win32_version_value = 0
    size_of_image = 0x2000
    size_of_headers = 0x0200
    checksum = 0
    subsystem = 2  # IMAGE_SUBSYSTEM_WINDOWS_GUI
    # DllCharacteristics: DYNAMIC_BASE (0x0040) | NX_COMPAT (0x0100)
    dll_characteristics = 0x0140
    size_of_stack_reserve = 0x100000
    size_of_stack_commit = 0x1000
    size_of_heap_reserve = 0x100000
    size_of_heap_commit = 0x1000
    loader_flags = 0
    number_of_rva_and_sizes = 16

    standard_and_windows_fields = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        magic,
        major_linker_version,
        minor_linker_version,
        size_of_code,
        size_of_init_data,
        size_of_uninit_data,
        entry_point_rva,
        base_of_code,
        image_base,
        section_alignment,
        file_alignment,
        major_os_version,
        minor_os_version,
        major_image_version,
        minor_image_version,
        major_subsystem_version,
        minor_subsystem_version,
        win32_version_value,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
        size_of_stack_reserve,
        size_of_stack_commit,
        size_of_heap_reserve,
        size_of_heap_commit,
        loader_flags,
        number_of_rva_and_sizes,
    )

    # 16 Data Directories (8 bytes each = 128 bytes)
    # Entry 4 (index 4) is IMAGE_DIRECTORY_ENTRY_SECURITY: (RVA=0, Size=0) -> UNSIGNED!
    data_directories = bytearray(16 * 8)

    optional_header = standard_and_windows_fields + bytes(data_directories)

    # ---------------------------------------------------------
    # 5. Section Header: .text (40 bytes)
    # ---------------------------------------------------------
    sect_name = b".text\x00\x00\x00"
    virtual_size = 0x0010
    virtual_address = 0x1000
    size_of_raw_data = 0x0200
    pointer_to_raw_data = 0x0200
    pointer_to_relocations = 0
    pointer_to_linenumbers = 0
    number_of_relocations = 0
    number_of_linenumbers = 0
    # Characteristics: CODE (0x00000020) | EXECUTE (0x20000000) | READ (0x40000000)
    sect_characteristics = 0x60000020

    section_header = struct.pack(
        "<8sIIIIIIHHI",
        sect_name,
        virtual_size,
        virtual_address,
        size_of_raw_data,
        pointer_to_raw_data,
        pointer_to_relocations,
        pointer_to_linenumbers,
        number_of_relocations,
        number_of_linenumbers,
        sect_characteristics,
    )

    # Combine headers up to 0x200 (file alignment boundary)
    header_content = (
        dos_header
        + dos_stub
        + pe_sig
        + coff_header
        + optional_header
        + section_header
    )
    headers_padding = b"\x00" * (0x0200 - len(header_content))
    all_headers = header_content + headers_padding

    # ---------------------------------------------------------
    # 6. Section Raw Data (.text section: 512 bytes)
    # ---------------------------------------------------------
    # Harmless x64 DllMain:
    #   mov eax, 1    (b"\xB8\x01\x00\x00\x00")
    #   ret           (b"\xC3")
    code_bytes = b"\xB8\x01\x00\x00\x00\xC3"
    raw_section = code_bytes + (b"\x90" * (0x0200 - len(code_bytes)))

    # Complete binary
    pe_dll_bytes = all_headers + raw_section

    if output_path:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        with open(output_path, "wb") as f:
            f.write(pe_dll_bytes)

    return pe_dll_bytes


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "dummy.dll"
    data = build_unsigned_pe_dll(out)
    print(f"[+] Successfully generated unsigned 64-bit PE DLL at '{out}' ({len(data)} bytes)")
