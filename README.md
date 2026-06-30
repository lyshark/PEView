# PEView Client SDK

PEView Client SDK is a high-performance PE/PE32+ structured parsing development toolkit targeting the Windows platform. Built on an independent PEView Server service architecture, it delivers process-isolated, standardized, full-spectrum static parsing capabilities for PE files.

This SDK encapsulates the low-level PE structure parsing logic for Windows and exposes a unified, concise, fully covered set of Python APIs. It supports a complete suite of reverse analysis features including reading basic PE metadata, parsing structural layouts, analyzing import/export tables, address conversion, signature searching, code disassembly, and module security attribute detection. It also allows users to integrate seamlessly with any MCP or large language model to implement intelligent analysis workflows.

## Prerequisites

1. Launch `PEView Server.exe` and run it with administrator privileges.
2. Install the Python client package via pip:

```bash
C:> pip install peview_client
C:> 
C:> pip show peview_client
Name: peview_client
Version: 4.0.0
Summary: A PE file analysis tool developed for Windows platforms, used to quickly parse PE (Portable Executable) file structures, disassemble code segments, convert virtual addresses/relative virtual addresses/file offset addresses, search signatures/strings, and assist in reverse engineering, malware analysis, and exploit development.
Home-page: http://peview.lyshark.com
Author: lyshark
Author-email: me@lyshark.com
License: MIT Licence
```

## API Reference

### open_file

Load a PE file into the server. This method is a mandatory pre-initialization step for all other PE parsing interfaces.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        res = pe.open_file(r"e://win32.exe")
        print("[+] File loaded successfully: ", res)
    finally:
        pe.close_file()
```

### get_basic_info

Retrieve global fundamental attributes including file size, creation timestamp, entry point, subsystem, PE validation flags, for quick PE validity verification and basic property inspection.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        info = pe.get_basic_info()
        print("[+] PE basic information: ", info)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] PE basic information:  {'file_basic_info': {'file_path': 'e://win32.exe', 'file_size_bytes': 13824, 'file_size_kb': 13.5, 'file_size_mb': 0.01318359375, 'file_attributes': 'file; ', 'create_time': '2026-06-30 15:47:07', 'modify_tim
e': '2026-06-30 15:47:53', 'map_base_address': '0x000f0000', 'map_base_address_dec': 983040}, 'pe_identifier': {'dos_signature_hex': '0x00005a4d', 'dos_signature_dec': 23117, 'dos_signature_desc': 'Valid DOS signature (MZ)', 'pe_header
_offset_hex': '0x000000f0', 'pe_header_offset_dec': 240, 'nt_signature_hex': '0x00004550', 'nt_signature_dec': 17744, 'nt_signature_desc': 'Valid PE signature (pe00)', 'machine_type_hex': '0x0000014c', 'machine_type_dec': 332, 'machine
_type_desc': 'x86 (32bit)', 'section_count': 4, 'nt_timestamp_hex': '0x6a4374a9', 'nt_timestamp_dec': 1782805673, 'nt_timestamp_desc': '1601-01-01 08:02:58', 'nt_characteristics_hex': '0x00000103', 'nt_characteristics_dec': 259, 'nt_ch
aracteristics_desc': 'Executable; '}, 'optional_header_info': {'entry_point_rva_hex': '0x0000152c', 'entry_point_rva_dec': 5420, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'image_size_hex': '0x00006000', 'image_size_dec
': 24576, 'section_alignment_hex': '0x00001000', 'section_alignment_dec': 4096, 'file_alignment_hex': '0x00000200', 'file_alignment_dec': 512, 'subsystem_hex': '0x00000002', 'subsystem_dec': 2, 'subsystem_desc': 'Windows GUI (Graphical
 interface)', 'dll_characteristics_hex': '0x00008000', 'dll_characteristics_dec': 32768, 'dll_characteristics_desc': 'No special features', 'stack_reserve_size_hex': '0x00100000', 'stack_reserve_size_dec': 1048576, 'stack_commit_size_h
ex': '0x00001000', 'stack_commit_size_dec': 4096, 'heap_reserve_size_hex': '0x00100000', 'heap_reserve_size_dec': 1048576, 'heap_commit_size_hex': '0x00001000', 'heap_commit_size_dec': 4096}, 'message': 'PE File basic information parsi
ng succeeded'}
```

### show_dos_head

Read full DOS header fields such as MZ signature and e_lfanew (offset to PE header). Validates DOS header integrity and fetches core offset information for the PE header.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        dos = pe.show_dos_head()
        print("[+] DOS header information: ", dos)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] DOS header information:  {'dos_header': {'e_magic': {'hex': '0x00005A4D', 'dec': 23117}, 'e_cblp': {'hex': '0x00000090', 'dec': 144}, 'e_cp': {'hex': '0x00000003', 'dec': 3}, 'e_crlc': {'hex': '0x00000000', 'dec': 0}, 'e_cparhdr':
{'hex': '0x00000004', 'dec': 4}, 'e_minalloc': {'hex': '0x00000000', 'dec': 0}, 'e_maxalloc': {'hex': '0x0000FFFF', 'dec': 65535}, 'e_ss': {'hex': '0x00000000', 'dec': 0}, 'e_sp': {'hex': '0x000000B8', 'dec': 184}, 'e_csum': {'hex': '0
x00000000', 'dec': 0}, 'e_ip': {'hex': '0x00000000', 'dec': 0}, 'e_cs': {'hex': '0x00000000', 'dec': 0}, 'e_lfarlc': {'hex': '0x00000040', 'dec': 64}, 'e_ovno': {'hex': '0x00000000', 'dec': 0}, 'e_res': [{'hex': '0x00000000', 'dec': 0}
, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}], 'e_oemid': {'hex': '0x00000000', 'dec': 0}, 'e_oeminfo': {'hex': '0x00000000', 'dec': 0}, 'e_res2': [{'hex': '0x00000000', 'dec': 0},
 {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}, {'h
ex': '0x00000000', 'dec': 0}, {'hex': '0x00000000', 'dec': 0}], 'e_lfanew': {'hex': '0x000000F0', 'dec': 240}}, 'message': 'DOS header parsing succeeded'}
```

### show_nt_head

Fetch complete core NT header data including PE signature, File Header, and Optional Header: machine architecture, section count, timestamp, entry point, image base address. This is the primary interface for parsing core PE structures.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        nt = pe.show_nt_head()
        print("[+] NT header information: ", nt)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] NT header information:  {'nt_head_info': {'nt_signature': {'nt_signature_hex': '0x00004550', 'nt_signature_dec': 17744, 'nt_signature_desc': 'Valid PE signature(PE00)'}, 'image_file_header': {'machine_hex': '0x0000014c', 'machine_d
ec': 332, 'machine_desc': 'x86 (32bit)', 'section_count_hex': '0x00000004', 'section_count_dec': 4, 'section_count_desc': 'Number of sections contained in PE file', 'timestamp_hex': '0x6a4374a9', 'timestamp_dec': 1782805673, 'timestamp
_desc': 'Tue Jun 30 15:47:53 2026', 'characteristics_hex': '0x00000103', 'characteristics_dec': 259, 'characteristics_desc': 'Remove relocation; Executable file; ', 'size_of_optional_header_hex': '0x000000e0', 'size_of_optional_header_
dec': 224, 'size_of_optional_header_desc': 'Byte size of optional header', 'number_of_symbols_hex': '0x00000000', 'number_of_symbols_dec': 0, 'number_of_symbols_desc': 'Number of symbols in the symbol table', 'pointer_to_symbol_table_h
ex': '0x00000000', 'pointer_to_symbol_table_dec': 0, 'pointer_to_symbol_table_desc': 'Offset of symbol table in file'}, 'image_optional_header': {'entry_point_rva_hex': '0x0000152c', 'entry_point_rva_dec': 5420, 'entry_point_va_hex': '
0x0040152c', 'entry_point_va_dec': 4199724, 'entry_point_desc': 'Virtual address of entry point (VA=mirror base address+RVA)', 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'image_base_desc': 'Preferred base address to loa
d into memory', 'size_of_image_hex': '0x00006000', 'size_of_image_dec': 24576, 'size_of_image_desc': 'Size of the entire image in memory (bytes)', 'base_of_code_hex': '0x00001000', 'base_of_code_dec': 4096, 'base_of_code_desc': 'Start
relative virtual address of code segment', 'base_of_data_hex': '0x00002000', 'base_of_data_dec': 8192, 'base_of_data_desc': 'Start relative virtual address of data segment', 'size_of_code_hex': '0x00000c00', 'size_of_code_dec': 3072, '
size_of_code_desc': 'Total size of code snippet (bytes)', 'size_of_initialized_data_hex': '0x00002a00', 'size_of_initialized_data_dec': 10752, 'size_of_initialized_data_desc': 'Size of initialized data segment (bytes)', 'size_of_uninit
ialized_data_hex': '0x00000000', 'size_of_uninitialized_data_dec': 0, 'size_of_uninitialized_data_desc': 'Size of uninitialized data segment (bytes)', 'section_alignment_hex': '0x00001000', 'section_alignment_dec': 4096, 'section_align
ment_desc': 'Alignment granularity of blocks in memory (bytes)', 'file_alignment_hex': '0x00000200', 'file_alignment_dec': 512, 'file_alignment_desc': 'Alignment granularity of blocks in file (bytes)', 'subsystem_hex': '0x00000002', 's
ubsystem_dec': 2, 'subsystem_desc': 'Windows GUI(Graphical interface)', 'size_of_headers_hex': '0x00000400', 'size_of_headers_dec': 1024, 'size_of_headers_desc': 'Total size of DOS header+nt header+section table', 'check_sum_hex': '0x0
0000000', 'check_sum_dec': 0, 'check_sum_desc': 'Used to verify file integrity (usually 0)', 'number_of_rva_and_sizes_hex': '0x00000010', 'number_of_rva_and_sizes_dec': 16, 'number_of_rva_and_sizes_desc': 'Number of data catalog entrie
s (typically 16)', 'major_linker_version_hex': '0x0000000c', 'major_linker_version_dec': 12, 'major_linker_version_desc': 'Linker major version', 'minor_linker_version_hex': '0x00000000', 'minor_linker_version_dec': 0, 'minor_linker_ve
rsion_desc': 'Linker minor version', 'version_info': {'operating_system_version': '6.0', 'operating_system_version_desc': 'Major version.6.Minor version.0', 'image_version': '0.0', 'image_version_desc': 'Major version.0.Minor version.0
', 'subsystem_version': '6.0', 'subsystem_version_desc': 'Major version.6.Minor version.0'}, 'win32_version_value_hex': '0x00000000', 'win32_version_value_dec': 0, 'win32_version_value_desc': 'Normally 0 (reserved)', 'dll_characteristi
cs_hex': '0x00008000', 'dll_characteristics_dec': 32768, 'dll_characteristics_desc': 'No special features', 'stack_heap_info': {'stack_reserve_size_hex': '0x00100000', 'stack_reserve_size_dec': 1048576, 'stack_reserve_size_desc': 'Rese
rved size of process stack', 'stack_commit_size_hex': '0x00001000', 'stack_commit_size_dec': 4096, 'stack_commit_size_desc': 'Initial commit size of process stack', 'heap_reserve_size_hex': '0x00100000', 'heap_reserve_size_dec': 104857
6, 'heap_reserve_size_desc': 'Reserved size of process heap', 'heap_commit_size_hex': '0x00001000', 'heap_commit_size_dec': 4096, 'heap_commit_size_desc': 'Initial commit size of process heap'}, 'loader_flags_hex': '0x00000000', 'loade
r_flags_dec': 0, 'loader_flags_desc': 'Obsolete (usually 0)'}}, 'message': 'NT Header parsing succeeded'}
```

### show_section

Retrieve details for all sections (.text/.data/.rdata etc.), including RVA, FOA, section flags and permission descriptions. Used to analyze code/data segment layout and read-write-execute permissions.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        sec = pe.show_section()
        print("[+] Section information: ", sec)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Section information:  {'section_info': {'section_count': 4, 'section_count_desc': 'PE Total number of sections contained in the file', 'sections': [{'section_index': 1, 'section_name': '.text', 'virtual_address_rva_hex': '0x0000100
0', 'virtual_address_rva_dec': 4096, 'virtual_address_rva_desc': 'Relative virtual address of the section in memory', 'virtual_size_hex': '0x00000afc', 'virtual_size_dec': 2812, 'virtual_size_desc': 'Total size of the section in memory
 (bytes)', 'raw_data_offset_foa_hex': '0x00000400', 'raw_data_offset_foa_dec': 1024, 'raw_data_offset_foa_desc': 'Actual offset of the section in the file', 'raw_data_size_hex': '0x00000c00', 'raw_data_size_dec': 3072, 'raw_data_size_d
esc': 'Storage size of the section in the file (bytes)', 'relocation_offset_foa_hex': '0x00000000', 'relocation_offset_foa_dec': 0, 'relocation_offset_foa_desc': 'Offset of section relocation information in the file (0 means none)', 'r
elocation_count': 0, 'relocation_count_desc': 'The number of relocation items contained in the section (0 means none)', 'linenumber_offset_foa_hex': '0x00000000', 'linenumber_offset_foa_dec': 0, 'linenumber_offset_foa_desc': 'Offset of
 section line number information in the file (0 means none)', 'linenumber_count': 0, 'linenumber_count_desc': 'Number of line number items contained in the section (0 means none)', 'characteristics_hex': '0x60000020', 'characteristics_
dec': 1610612768, 'characteristics_desc': 'Code section; Executable; readable; '}, {'section_index': 2, 'section_name': '.rdata', 'virtual_address_rva_hex': '0x00002000', 'virtual_address_rva_dec': 8192, 'virtual_address_rva_desc': 'Re
lative virtual address of the section in memory', 'virtual_size_hex': '0x000006ea', 'virtual_size_dec': 1770, 'virtual_size_desc': 'Total size of the section in memory (bytes)', 'raw_data_offset_foa_hex': '0x00001000', 'raw_data_offset
_foa_dec': 4096, 'raw_data_offset_foa_desc': 'Actual offset of the section in the file', 'raw_data_size_hex': '0x00000800', 'raw_data_size_dec': 2048, 'raw_data_size_desc': 'Storage size of the section in the file (bytes)', 'relocation
_offset_foa_hex': '0x00000000', 'relocation_offset_foa_dec': 0, 'relocation_offset_foa_desc': 'Offset of section relocation information in the file (0 means none)', 'relocation_count': 0, 'relocation_count_desc': 'The number of relocat
ion items contained in the section (0 means none)', 'linenumber_offset_foa_hex': '0x00000000', 'linenumber_offset_foa_dec': 0, 'linenumber_offset_foa_desc': 'Offset of section line number information in the file (0 means none)', 'linen
umber_count': 0, 'linenumber_count_desc': 'Number of line number items contained in the section (0 means none)', 'characteristics_hex': '0x40000040', 'characteristics_dec': 1073741888, 'characteristics_desc': 'Initialized data; readabl
e; '}, {'section_index': 3, 'section_name': '.data', 'virtual_address_rva_hex': '0x00003000', 'virtual_address_rva_dec': 12288, 'virtual_address_rva_desc': 'Relative virtual address of the section in memory', 'virtual_size_hex': '0x000
00520', 'virtual_size_dec': 1312, 'virtual_size_desc': 'Total size of the section in memory (bytes)', 'raw_data_offset_foa_hex': '0x00001800', 'raw_data_offset_foa_dec': 6144, 'raw_data_offset_foa_desc': 'Actual offset of the section i
n the file', 'raw_data_size_hex': '0x00000200', 'raw_data_size_dec': 512, 'raw_data_size_desc': 'Storage size of the section in the file (bytes)', 'relocation_offset_foa_hex': '0x00000000', 'relocation_offset_foa_dec': 0, 'relocation_o
ffset_foa_desc': 'Offset of section relocation information in the file (0 means none)', 'relocation_count': 0, 'relocation_count_desc': 'The number of relocation items contained in the section (0 means none)', 'linenumber_offset_foa_he
x': '0x00000000', 'linenumber_offset_foa_dec': 0, 'linenumber_offset_foa_desc': 'Offset of section line number information in the file (0 means none)', 'linenumber_count': 0, 'linenumber_count_desc': 'Number of line number items contai
ned in the section (0 means none)', 'characteristics_hex': '0x00000000', 'characteristics_dec': 3221225536, 'characteristics_desc': 'Initialized data; readable; Writable; '}, {'section_index': 4, 'section_name': '.rsrc', 'virtual_addre
ss_rva_hex': '0x00004000', 'virtual_address_rva_dec': 16384, 'virtual_address_rva_desc': 'Relative virtual address of the section in memory', 'virtual_size_hex': '0x00001ba0', 'virtual_size_dec': 7072, 'virtual_size_desc': 'Total size
of the section in memory (bytes)', 'raw_data_offset_foa_hex': '0x00001a00', 'raw_data_offset_foa_dec': 6656, 'raw_data_offset_foa_desc': 'Actual offset of the section in the file', 'raw_data_size_hex': '0x00001c00', 'raw_data_size_dec'
: 7168, 'raw_data_size_desc': 'Storage size of the section in the file (bytes)', 'relocation_offset_foa_hex': '0x00000000', 'relocation_offset_foa_dec': 0, 'relocation_offset_foa_desc': 'Offset of section relocation information in the
file (0 means none)', 'relocation_count': 0, 'relocation_count_desc': 'The number of relocation items contained in the section (0 means none)', 'linenumber_offset_foa_hex': '0x00000000', 'linenumber_offset_foa_dec': 0, 'linenumber_offs
et_foa_desc': 'Offset of section line number information in the file (0 means none)', 'linenumber_count': 0, 'linenumber_count_desc': 'Number of line number items contained in the section (0 means none)', 'characteristics_hex': '0x4000
0040', 'characteristics_dec': 1073741888, 'characteristics_desc': 'Initialized data; readable; '}]}, 'message': 'Section information parsing succeeded'}
```

### show_optional_data_directory

Read all 16 PE data directories (import table, export table, resource table, relocation table, etc.) with their respective RVAs and validity flags, enabling fast lookup of critical PE table locations.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        dir_info = pe.show_optional_data_directory()
        print("[+] Data Directory Table: ", dir_info)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Data Directory Table:  {'optional_data_directory_info': {'data_directory_count': 16, 'data_directory_count_desc': 'Total number of data directory entries defined in PE optional header (usually 16)', 'data_directories': [{'directory
_index': 1, 'standard_name': 'Export Table', 'description': 'Contains exported functions and symbol information for calling by other modules', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_
desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva
)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'S
ize of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 2, 'standard_name': 'Import Table', 'description': 'Contains information about
 imported DLLs and functions, which needs to be resolved during loading', 'virtual_address_rva_hex': '0x000021d4', 'virtual_address_rva_dec': 8660, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'vir
tual_address_va_hex': '0x004021d4', 'virtual_address_va_dec': 4202964, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x000011d4', 'file_offset_foa_de
c': 4564, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 80, 'size_hex': '0x00000050', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)',
 'is_valid': True, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 3, 'standard_name': 'Resource Table', 'description': 'Contains index information of program resources (such as icons, strings, dialog boxes, etc
.)', 'virtual_address_rva_hex': '0x00004000', 'virtual_address_rva_dec': 16384, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00404000', 'virtual_address_va_dec': 421068
8, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00001a00', 'file_offset_foa_dec': 6656, 'file_offset_foa_desc': 'The actual offset address of the
directory in the file (converted from RVA)', 'size_dec': 7072, 'size_hex': '0x00001ba0', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': True, 'is_valid_desc': 'Valid (RVA and size are not 0
)'}, {'directory_index': 4, 'standard_name': 'Exception Table', 'description': 'Contains exception handling-related structures for exception catching and handling', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0,
 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (m
irror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x0000
0000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 5, 'standard_name': 'Security Table', 'description': 'Co
ntains security information such as digital signatures for verifying file integrity', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memo
ry', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa
_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual
 data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 6, 'standard_name': 'Base Relocation Table', 'description': 'Contains base address relocation information, used to correct when the mod
ule loading address is different from the default', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x
00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_fo
a_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_va
lid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 7, 'standard_name': 'Debug Table', 'description': 'Contains debugging information (such as debug symbol path, type, etc.)', 'virtual_address_rva_hex': '0x00000000', 'vir
tual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of t
he directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec
': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 8, 'standard_name': 'Architectu
re', 'description': 'Copyright information string (usually in Unicode format)', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', '
virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec':
 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)
', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 9, 'standard_name': 'Global Pointer', 'description': 'Global pointers (used for accessing global variables in certain architectures)', 'virtu
al_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_v
a_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in th
e file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_
index': 10, 'standard_name': 'TLS Table', 'description': 'Thread Local Storage (TLS) information, used for thread-private data', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relati
ve virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offs
et_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes o
ccupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 11, 'standard_name': 'Load Configuration Table', 'description': 'Load configuration informat
ion (such as security cookies, SEH verification, etc.)', 'virtual_address_rva_hex': '0x00002110', 'virtual_address_rva_dec': 8464, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_h
ex': '0x00402110', 'virtual_address_va_dec': 4202768, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00001110', 'file_offset_foa_dec': 4368, 'file_o
ffset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 64, 'size_hex': '0x00000040', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': True
, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 12, 'standard_name': 'Bound Import Table', 'description': 'Bound import table, pre-resolved imported function addresses to accelerate loading', 'virtual_address_
rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'A
bsolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (con
verted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 13,
 'standard_name': 'Import Address Table', 'description': 'Import Address Table (IAT), which stores the memory addresses of actual imported functions', 'virtual_address_rva_hex': '0x00002000', 'virtual_address_rva_dec': 8192, 'virtual_a
ddress_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00402000', 'virtual_address_va_dec': 4202496, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror
 base address+rva)', 'file_offset_foa_hex': '0x00001000', 'file_offset_foa_dec': 4096, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 232, 'size_hex': '0x000000e8', 's
ize_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': True, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 14, 'standard_name': 'Delay Import Descriptor', 'description': 'De
lay Import Descriptor, used for delayed loading of DLLs (loaded at runtime)', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'vi
rtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4
294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)',
 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directory_index': 15, 'standard_name': 'COM Descriptor', 'description': 'COM component description information (such as CLSID, interface information, etc.)', 'vi
rtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory', 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_addres
s_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in
 the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual data)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}, {'directo
ry_index': 16, 'standard_name': 'Reserved', 'description': 'Reserved and unused', 'virtual_address_rva_hex': '0x00000000', 'virtual_address_rva_dec': 0, 'virtual_address_rva_desc': 'Relative virtual address of the directory in memory',
 'virtual_address_va_hex': '0x00000000', 'virtual_address_va_dec': 0, 'virtual_address_va_desc': 'Absolute virtual address of the directory in memory (mirror base address+rva)', 'file_offset_foa_hex': '0x00000000', 'file_offset_foa_dec
': 4294967295, 'file_offset_foa_desc': 'The actual offset address of the directory in the file (converted from RVA)', 'size_dec': 0, 'size_hex': '0x00000000', 'size_desc': 'Size of bytes occupied by the directory (0 means no actual dat
a)', 'is_valid': False, 'is_valid_desc': 'Valid (RVA and size are not 0)'}]}, 'message': 'Data directory table information parsing succeeded'}
```

### show_import_by_dll

List all dependent DLLs alongside INT/IAT addresses and count statistics, for fast enumeration of all external module dependencies of the PE file.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        dlls = pe.show_import_by_dll()
        print("[+] Imported DLL list: ", dlls)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Imported DLL list:  {'import_by_dll_info': {'import_dll_count': 3, 'import_dll_count_desc': 'Total number of DLLs imported from PE file', 'import_dlls': [{'dll_index': 1, 'dll_name': 'USER32.dll', 'int_rva_hex': '0x000022bc', 'int_
rva_dec': 8892, 'int_rva_desc': 'Relative virtual address of import name table (int)', 'int_foa_hex': '0x000012bc', 'int_foa_dec': 4796, 'int_foa_desc': 'File offset address of import name table (int)', 'int_va_hex': '0x004022bc', 'int
_va_dec': 4203196, 'int_va_desc': 'Memory virtual address of import name table (int) (image base address+rva)', 'iat_rva_hex': '0x00002098', 'iat_rva_dec': 8344, 'iat_rva_desc': 'Import the relative virtual address of the address table
 (IAT)', 'iat_foa_hex': '0x00001098', 'iat_foa_dec': 4248, 'iat_foa_desc': 'File offset address of import address table (IAT)', 'iat_va_hex': '0x00402098', 'iat_va_dec': 4202648, 'iat_va_desc': 'Import the memory virtual address of the
 address table (IAT) (image base address+rva)', 'timestamp_hex': '0x00000000', 'timestamp_dec': 0, 'timestamp_utc': 'Unbound (0)', 'timestamp_desc': 'Unbound (dynamically resolved on load)', 'forwarder_chain_hex': '0x00000000', 'forwar
der_chain_dec': 0, 'forwarder_chain_desc': 'Not set(0)', 'dll_name_rva_hex': '0x00002446', 'dll_name_rva_dec': 9286, 'dll_name_foa_hex': '0x00001446', 'dll_name_foa_dec': 5190, 'dll_name_addr_desc': 'Address information of DLL name str
ing in file'}, {'dll_index': 2, 'dll_name': 'MSVCR120.dll', 'int_rva_hex': '0x00002248', 'int_rva_dec': 8776, 'int_rva_desc': 'Relative virtual address of import name table (int)', 'int_foa_hex': '0x00001248', 'int_foa_dec': 4680, 'int
_foa_desc': 'File offset address of import name table (int)', 'int_va_hex': '0x00402248', 'int_va_dec': 4203080, 'int_va_desc': 'Memory virtual address of import name table (int) (image base address+rva)', 'iat_rva_hex': '0x00002024',
'iat_rva_dec': 8228, 'iat_rva_desc': 'Import the relative virtual address of the address table (IAT)', 'iat_foa_hex': '0x00001024', 'iat_foa_dec': 4132, 'iat_foa_desc': 'File offset address of import address table (IAT)', 'iat_va_hex':
 '0x00402024', 'iat_va_dec': 4202532, 'iat_va_desc': 'Import the memory virtual address of the address table (IAT) (image base address+rva)', 'timestamp_hex': '0x00000000', 'timestamp_dec': 0, 'timestamp_utc': 'Unbound (0)', 'timestamp
_desc': 'Unbound (dynamically resolved on load)', 'forwarder_chain_hex': '0x00000000', 'forwarder_chain_dec': 0, 'forwarder_chain_desc': 'Not set(0)', 'dll_name_rva_hex': '0x00002562', 'dll_name_rva_dec': 9570, 'dll_name_foa_hex': '0x0
0001562', 'dll_name_foa_dec': 5474, 'dll_name_addr_desc': 'Address information of DLL name string in file'}, {'dll_index': 3, 'dll_name': 'KERNEL32.dll', 'int_rva_hex': '0x00002224', 'int_rva_dec': 8740, 'int_rva_desc': 'Relative virtu
al address of import name table (int)', 'int_foa_hex': '0x00001224', 'int_foa_dec': 4644, 'int_foa_desc': 'File offset address of import name table (int)', 'int_va_hex': '0x00402224', 'int_va_dec': 4203044, 'int_va_desc': 'Memory virtu
al address of import name table (int) (image base address+rva)', 'iat_rva_hex': '0x00002000', 'iat_rva_dec': 8192, 'iat_rva_desc': 'Import the relative virtual address of the address table (IAT)', 'iat_foa_hex': '0x00001000', 'iat_foa_
dec': 4096, 'iat_foa_desc': 'File offset address of import address table (IAT)', 'iat_va_hex': '0x00402000', 'iat_va_dec': 4202496, 'iat_va_desc': 'Import the memory virtual address of the address table (IAT) (image base address+rva)',
 'timestamp_hex': '0x00000000', 'timestamp_dec': 0, 'timestamp_utc': 'Unbound (0)', 'timestamp_desc': 'Unbound (dynamically resolved on load)', 'forwarder_chain_hex': '0x00000000', 'forwarder_chain_dec': 0, 'forwarder_chain_desc': 'Not
 set(0)', 'dll_name_rva_hex': '0x000026dc', 'dll_name_rva_dec': 9948, 'dll_name_foa_hex': '0x000016dc', 'dll_name_foa_dec': 5852, 'dll_name_addr_desc': 'Address information of DLL name string in file'}]}, 'message': 'Import DLL list re
solved successfully'}
```

### show_import_by_name

Query all imported functions under a single target DLL (both name-based and ordinal imports) for precise parsing of function imports from a specified dependency module.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        funcs = pe.show_import_by_name("KERNEL32.dll")
        print("[+] Imported functions from KERNEL32: ", funcs)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Imported functions from KERNEL32:  {'message': 'The import function of the specified DLL resolved successfully', 'import_by_name_info': {'target_dll': 'KERNEL32.dll', 'dll_found': True, 'import_function_count': 8, 'import_function_
count_desc': 'Total number of import functions for the specified DLL', 'import_functions': [{'import_type': 'Name import', 'hint_value': 877, 'function_info': 'IsProcessorFeaturePresent', 'function_index': 1, 'int_rva_hex': '0x00002224
', 'int_rva_dec': 8740, 'int_foa_hex': '0x00001224', 'int_foa_dec': 4644, 'int_va_hex': '0x00402224', 'int_va_dec': 4203044, 'iat_rva_hex': '0x00002000', 'iat_rva_dec': 8192, 'iat_foa_hex': '0x00001000', 'iat_foa_dec': 4096, 'iat_va_he
x': '0x00402000', 'iat_va_dec': 4202496}, {'import_type': 'Name import', 'hint_value': 871, 'function_info': 'IsDebuggerPresent', 'function_index': 2, 'int_rva_hex': '0x00002228', 'int_rva_dec': 8744, 'int_foa_hex': '0x00001228', 'int_
foa_dec': 4648, 'int_va_hex': '0x00402228', 'int_va_dec': 4203048, 'iat_rva_hex': '0x00002004', 'iat_rva_dec': 8196, 'iat_foa_hex': '0x00001004', 'iat_foa_dec': 4100, 'iat_va_hex': '0x00402004', 'iat_va_dec': 4202500}, {'import_type':
'Name import', 'hint_value': 254, 'function_info': 'DecodePointer', 'function_index': 3, 'int_rva_hex': '0x0000222c', 'int_rva_dec': 8748, 'int_foa_hex': '0x0000122c', 'int_foa_dec': 4652, 'int_va_hex': '0x0040222c', 'int_va_dec': 4203
052, 'iat_rva_hex': '0x00002008', 'iat_rva_dec': 8200, 'iat_foa_hex': '0x00001008', 'iat_foa_dec': 4104, 'iat_va_hex': '0x00402008', 'iat_va_dec': 4202504}, {'import_type': 'Name import', 'hint_value': 726, 'function_info': 'GetSystemT
imeAsFileTime', 'function_index': 4, 'int_rva_hex': '0x00002230', 'int_rva_dec': 8752, 'int_foa_hex': '0x00001230', 'int_foa_dec': 4656, 'int_va_hex': '0x00402230', 'int_va_dec': 4203056, 'iat_rva_hex': '0x0000200c', 'iat_rva_dec': 820
4, 'iat_foa_hex': '0x0000100c', 'iat_foa_dec': 4108, 'iat_va_hex': '0x0040200c', 'iat_va_dec': 4202508}, {'import_type': 'Name import', 'hint_value': 526, 'function_info': 'GetCurrentThreadId', 'function_index': 5, 'int_rva_hex': '0x00
002234', 'int_rva_dec': 8756, 'int_foa_hex': '0x00001234', 'int_foa_dec': 4660, 'int_va_hex': '0x00402234', 'int_va_dec': 4203060, 'iat_rva_hex': '0x00002010', 'iat_rva_dec': 8208, 'iat_foa_hex': '0x00001010', 'iat_foa_dec': 4112, 'iat
_va_hex': '0x00402010', 'iat_va_dec': 4202512}, {'import_type': 'Name import', 'hint_value': 522, 'function_info': 'GetCurrentProcessId', 'function_index': 6, 'int_rva_hex': '0x00002238', 'int_rva_dec': 8760, 'int_foa_hex': '0x00001238
', 'int_foa_dec': 4664, 'int_va_hex': '0x00402238', 'int_va_dec': 4203064, 'iat_rva_hex': '0x00002014', 'iat_rva_dec': 8212, 'iat_foa_hex': '0x00001014', 'iat_foa_dec': 4116, 'iat_va_hex': '0x00402014', 'iat_va_dec': 4202516}, {'import
_type': 'Name import', 'hint_value': 1069, 'function_info': 'QueryPerformanceCounter', 'function_index': 7, 'int_rva_hex': '0x0000223c', 'int_rva_dec': 8764, 'int_foa_hex': '0x0000123c', 'int_foa_dec': 4668, 'int_va_hex': '0x0040223c',
 'int_va_dec': 4203068, 'iat_rva_hex': '0x00002018', 'iat_rva_dec': 8216, 'iat_foa_hex': '0x00001018', 'iat_foa_dec': 4120, 'iat_va_hex': '0x00402018', 'iat_va_dec': 4202520}, {'import_type': 'Name import', 'hint_value': 289, 'function
_info': 'EncodePointer', 'function_index': 8, 'int_rva_hex': '0x00002240', 'int_rva_dec': 8768, 'int_foa_hex': '0x00001240', 'int_foa_dec': 4672, 'int_va_hex': '0x00402240', 'int_va_dec': 4203072, 'iat_rva_hex': '0x0000201c', 'iat_rva_
dec': 8220, 'iat_foa_hex': '0x0000101c', 'iat_foa_dec': 4124, 'iat_va_hex': '0x0040201c', 'iat_va_dec': 4202524}]}}
```

### show_import_by_function

Perform fuzzy or exact matching for target imported functions; supports ordinal matching and case sensitivity toggle for rapid retrieval of specific imported routines.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.show_import_by_function("CreateFileA", case_sensitive=False)
        print("[+] Matched imported functions: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Matched imported functions:  {'message': 'No matching import function found', 'import_by_function_info': {'target_function': 'CreateFileA', 'case_sensitive': False, 'check_ordinal': True, 'match_count': 0, 'matched_functions': [],
'reason': 'No matching function was found in the import table (check function name/sequence number or matching configuration)'}}
```

### show_import_all

Fetch complete full-structure import table data including all DLLs and their associated imported functions in one call, optimized for batch parsing workflows.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        all_import = pe.show_import_all()
        print("[+] Full import table: ", all_import)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Full import table:  {'message': 'Successfully traverse all import modules and functions', 'import_all_info': {'import_table_global': {'import_dir_rva_hex': '0x000021d4', 'import_dir_rva_dec': 8660, 'import_dir_foa_hex': '0x000011d4
', 'import_dir_foa_dec': 4564, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304}, 'import_module_count': 3, 'import_modules': [{'dll_name': 'USER32.dll', 'dll_index': 1, 'descriptor_rva_hex': '0x000011d4', 'descriptor_rva_dec'
: 4564, 'descriptor_foa_hex': '0x000005d4', 'descriptor_foa_dec': 1492, 'timestamp_hex': '0x00000000', 'timestamp_dec': 0, 'timestamp_desc': 'Unbound', 'forwarder_chain_hex': '0x00000000', 'forwarder_chain_dec': 0, 'forwarder_chain_des
c': 'Presence forwarding', 'int_rva_hex': '0x000022bc', 'int_rva_dec': 8892, 'int_foa_hex': '0x000012bc', 'int_foa_dec': 4796, 'iat_rva_hex': '0x00002098', 'iat_rva_dec': 8344, 'iat_foa_hex': '0x00001098', 'iat_foa_dec': 4248, 'functio
n_count': 19, 'import_functions': [{'function_index': 1, 'import_type': 'Name import', 'hint_value': 231, 'function_info': 'EndDialog', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000243a', 'int_raw_data_dec': 927
4, 'int_va_hex': '0x004022bc', 'int_va_dec': 4203196, 'iat_raw_data_hex': '0x0000243a', 'iat_raw_data_dec': 9274, 'iat_va_hex': '0x00402098', 'iat_va_dec': 4202648}, {'function_index': 2, 'import_type': 'Name import', 'hint_value': 625
, 'function_info': 'PostQuitMessage', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002428', 'int_raw_data_dec': 9256, 'int_va_hex': '0x004022c0', 'int_va_dec': 4203200, 'iat_raw_data_hex': '0x00002428', 'iat_raw_d
ata_dec': 9256, 'iat_va_hex': '0x0040209c', 'iat_va_dec': 4202652}, {'function_index': 3, 'import_type': 'Name import', 'hint_value': 233, 'function_info': 'EndPaint', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00
00241c', 'int_raw_data_dec': 9244, 'int_va_hex': '0x004022c4', 'int_va_dec': 4203204, 'iat_raw_data_hex': '0x0000241c', 'iat_raw_data_dec': 9244, 'iat_va_hex': '0x004020a0', 'iat_va_dec': 4202656}, {'function_index': 4, 'import_type':
'Name import', 'hint_value': 14, 'function_info': 'BeginPaint', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000240e', 'int_raw_data_dec': 9230, 'int_va_hex': '0x004022c8', 'int_va_dec': 4203208, 'iat_raw_data_hex'
: '0x0000240e', 'iat_raw_data_dec': 9230, 'iat_va_hex': '0x004020a4', 'iat_va_dec': 4202660}, {'function_index': 5, 'import_type': 'Name import', 'hint_value': 161, 'function_info': 'DefWindowProcW', 'status': 'Existing function forwar
ding', 'int_raw_data_hex': '0x000023fc', 'int_raw_data_dec': 9212, 'int_va_hex': '0x004022cc', 'int_va_dec': 4203212, 'iat_raw_data_hex': '0x000023fc', 'iat_raw_data_dec': 9212, 'iat_va_hex': '0x004020a8', 'iat_va_dec': 4202664}, {'fun
ction_index': 6, 'import_type': 'Name import', 'hint_value': 173, 'function_info': 'DestroyWindow', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000023ec', 'int_raw_data_dec': 9196, 'int_va_hex': '0x004022d0', 'int_
va_dec': 4203216, 'iat_raw_data_hex': '0x000023ec', 'iat_raw_data_dec': 9196, 'iat_va_hex': '0x004020ac', 'iat_va_dec': 4202668}, {'function_index': 7, 'import_type': 'Name import', 'hint_value': 178, 'function_info': 'DialogBoxParamW'
, 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000023da', 'int_raw_data_dec': 9178, 'int_va_hex': '0x004022d4', 'int_va_dec': 4203220, 'iat_raw_data_hex': '0x000023da', 'iat_raw_data_dec': 9178, 'iat_va_hex': '0x004
020b0', 'iat_va_dec': 4202672}, {'function_index': 8, 'import_type': 'Name import', 'hint_value': 855, 'function_info': 'UpdateWindow', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000023ca', 'int_raw_data_dec': 916
2, 'int_va_hex': '0x004022d8', 'int_va_dec': 4203224, 'iat_raw_data_hex': '0x000023ca', 'iat_raw_data_dec': 9162, 'iat_va_hex': '0x004020b4', 'iat_va_dec': 4202676}, {'function_index': 9, 'import_type': 'Name import', 'hint_value': 800
, 'function_info': 'ShowWindow', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000023bc', 'int_raw_data_dec': 9148, 'int_va_hex': '0x004022dc', 'int_va_dec': 4203228, 'iat_raw_data_hex': '0x000023bc', 'iat_raw_data_d
ec': 9148, 'iat_va_hex': '0x004020b8', 'iat_va_dec': 4202680}, {'function_index': 10, 'import_type': 'Name import', 'hint_value': 113, 'function_info': 'CreateWindowExW', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0
x000023aa', 'int_raw_data_dec': 9130, 'int_va_hex': '0x004022e0', 'int_va_dec': 4203232, 'iat_raw_data_hex': '0x000023aa', 'iat_raw_data_dec': 9130, 'iat_va_hex': '0x004020bc', 'iat_va_dec': 4202684}, {'function_index': 11, 'import_typ
e': 'Name import', 'hint_value': 649, 'function_info': 'RegisterClassExW', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002396', 'int_raw_data_dec': 9110, 'int_va_hex': '0x004022e4', 'int_va_dec': 4203236, 'iat_ra
w_data_hex': '0x00002396', 'iat_raw_data_dec': 9110, 'iat_va_hex': '0x004020c0', 'iat_va_dec': 4202688}, {'function_index': 12, 'import_type': 'Name import', 'hint_value': 545, 'function_info': 'LoadCursorW', 'status': 'Existing functi
on forwarding', 'int_raw_data_hex': '0x00002388', 'int_raw_data_dec': 9096, 'int_va_hex': '0x004022e8', 'int_va_dec': 4203240, 'iat_raw_data_hex': '0x00002388', 'iat_raw_data_dec': 9096, 'iat_va_hex': '0x004020c4', 'iat_va_dec': 420269
2}, {'function_index': 13, 'import_type': 'Name import', 'hint_value': 547, 'function_info': 'LoadIconW', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000237c', 'int_raw_data_dec': 9084, 'int_va_hex': '0x004022ec',
 'int_va_dec': 4203244, 'iat_raw_data_hex': '0x0000237c', 'iat_raw_data_dec': 9084, 'iat_va_hex': '0x004020c8', 'iat_va_dec': 4202696}, {'function_index': 14, 'import_type': 'Name import', 'hint_value': 181, 'function_info': 'DispatchM
essageW', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002368', 'int_raw_data_dec': 9064, 'int_va_hex': '0x004022f0', 'int_va_dec': 4203248, 'iat_raw_data_hex': '0x00002368', 'iat_raw_data_dec': 9064, 'iat_va_hex'
: '0x004020cc', 'iat_va_dec': 4202700}, {'function_index': 15, 'import_type': 'Name import', 'hint_value': 831, 'function_info': 'TranslateMessage', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002354', 'int_raw_d
ata_dec': 9044, 'int_va_hex': '0x004022f4', 'int_va_dec': 4203252, 'iat_raw_data_hex': '0x00002354', 'iat_raw_data_dec': 9044, 'iat_va_hex': '0x004020d0', 'iat_va_dec': 4202704}, {'function_index': 16, 'import_type': 'Name import', 'hi
nt_value': 829, 'function_info': 'TranslateAcceleratorW', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000233c', 'int_raw_data_dec': 9020, 'int_va_hex': '0x004022f8', 'int_va_dec': 4203256, 'iat_raw_data_hex': '0x0
000233c', 'iat_raw_data_dec': 9020, 'iat_va_hex': '0x004020d4', 'iat_va_dec': 4202708}, {'function_index': 17, 'import_type': 'Name import', 'hint_value': 371, 'function_info': 'GetMessageW', 'status': 'Existing function forwarding', '
int_raw_data_hex': '0x0000232e', 'int_raw_data_dec': 9006, 'int_va_hex': '0x004022fc', 'int_va_dec': 4203260, 'iat_raw_data_hex': '0x0000232e', 'iat_raw_data_dec': 9006, 'iat_va_hex': '0x004020d8', 'iat_va_dec': 4202712}, {'function_in
dex': 18, 'import_type': 'Name import', 'hint_value': 539, 'function_info': 'LoadAcceleratorsW', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000231a', 'int_raw_data_dec': 8986, 'int_va_hex': '0x00402300', 'int_va_
dec': 4203264, 'iat_raw_data_hex': '0x0000231a', 'iat_raw_data_dec': 8986, 'iat_va_hex': '0x004020dc', 'iat_va_dec': 4202716}, {'function_index': 19, 'import_type': 'Name import', 'hint_value': 560, 'function_info': 'LoadStringW', 'sta
tus': 'Existing function forwarding', 'int_raw_data_hex': '0x0000230c', 'int_raw_data_dec': 8972, 'int_va_hex': '0x00402304', 'int_va_dec': 4203268, 'iat_raw_data_hex': '0x0000230c', 'iat_raw_data_dec': 8972, 'iat_va_hex': '0x004020e0'
, 'iat_va_dec': 4202720}]}, {'dll_name': 'MSVCR120.dll', 'dll_index': 2, 'descriptor_rva_hex': '0x000011e8', 'descriptor_rva_dec': 4584, 'descriptor_foa_hex': '0x000005e8', 'descriptor_foa_dec': 1512, 'timestamp_hex': '0x00000000', 'ti
mestamp_dec': 0, 'timestamp_desc': 'Unbound', 'forwarder_chain_hex': '0x00000000', 'forwarder_chain_dec': 0, 'forwarder_chain_desc': 'Presence forwarding', 'int_rva_hex': '0x00002248', 'int_rva_dec': 8776, 'int_foa_hex': '0x00001248',
'int_foa_dec': 4680, 'iat_rva_hex': '0x00002024', 'iat_rva_dec': 8228, 'iat_foa_hex': '0x00001024', 'iat_foa_dec': 4132, 'function_count': 28, 'import_functions': [{'function_index': 1, 'import_type': 'Name import', 'hint_value': 427,
'function_info': '__crtTerminateProcess', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002614', 'int_raw_data_dec': 9748, 'int_va_hex': '0x00402248', 'int_va_dec': 4203080, 'iat_raw_data_hex': '0x00002614', 'iat_r
aw_data_dec': 9748, 'iat_va_hex': '0x00402024', 'iat_va_dec': 4202532}, {'function_index': 2, 'import_type': 'Name import', 'hint_value': 428, 'function_info': '__crtUnhandledException', 'status': 'Existing function forwarding', 'int_r
aw_data_hex': '0x000025fa', 'int_raw_data_dec': 9722, 'int_va_hex': '0x0040224c', 'int_va_dec': 4203084, 'iat_raw_data_hex': '0x000025fa', 'iat_raw_data_dec': 9722, 'iat_va_hex': '0x00402028', 'iat_va_dec': 4202536}, {'function_index':
 3, 'import_type': 'Name import', 'hint_value': 592, 'function_info': '_crt_debugger_hook', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000025e4', 'int_raw_data_dec': 9700, 'int_va_hex': '0x00402250', 'int_va_dec':
 4203088, 'iat_raw_data_hex': '0x000025e4', 'iat_raw_data_dec': 9700, 'iat_va_hex': '0x0040202c', 'iat_va_dec': 4202540}, {'function_index': 4, 'import_type': 'Name import', 'hint_value': 634, 'function_info': '_except_handler4_common'
, 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000025ca', 'int_raw_data_dec': 9674, 'int_va_hex': '0x00402254', 'int_va_dec': 4203092, 'iat_raw_data_hex': '0x000025ca', 'iat_raw_data_dec': 9674, 'iat_va_hex': '0x004
02030', 'iat_va_dec': 4202544}, {'function_index': 5, 'import_type': 'Name import', 'hint_value': 579, 'function_info': '_controlfp_s', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000025ba', 'int_raw_data_dec': 965
8, 'int_va_hex': '0x00402258', 'int_va_dec': 4203096, 'iat_raw_data_hex': '0x000025ba', 'iat_raw_data_dec': 9658, 'iat_va_hex': '0x00402034', 'iat_va_dec': 4202548}, {'function_index': 6, 'import_type': 'Name import', 'hint_value': 788
, 'function_info': '_invoke_watson', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000025a8', 'int_raw_data_dec': 9640, 'int_va_hex': '0x0040225c', 'int_va_dec': 4203100, 'iat_raw_data_hex': '0x000025a8', 'iat_raw_da
ta_dec': 9640, 'iat_va_hex': '0x00402038', 'iat_va_dec': 4202552}, {'function_index': 7, 'import_type': 'Name import', 'hint_value': 1082, 'function_info': '_onexit', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000
0259e', 'int_raw_data_dec': 9630, 'int_va_hex': '0x00402260', 'int_va_dec': 4203104, 'iat_raw_data_hex': '0x0000259e', 'iat_raw_data_dec': 9630, 'iat_va_hex': '0x0040203c', 'iat_va_dec': 4202556}, {'function_index': 8, 'import_type': '
Name import', 'hint_value': 430, 'function_info': '__dllonexit', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002590', 'int_raw_data_dec': 9616, 'int_va_hex': '0x00402264', 'int_va_dec': 4203108, 'iat_raw_data_hex
': '0x00002590', 'iat_raw_data_dec': 9616, 'iat_va_hex': '0x00402040', 'iat_va_dec': 4202560}, {'function_index': 9, 'import_type': 'Name import', 'hint_value': 558, 'function_info': '_calloc_crt', 'status': 'Existing function forwardi
ng', 'int_raw_data_hex': '0x00002582', 'int_raw_data_dec': 9602, 'int_va_hex': '0x00402268', 'int_va_dec': 4203112, 'iat_raw_data_hex': '0x00002582', 'iat_raw_data_dec': 9602, 'iat_va_hex': '0x00402044', 'iat_va_dec': 4202564}, {'funct
ion_index': 10, 'import_type': 'Name import', 'hint_value': 1284, 'function_info': '_unlock', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002578', 'int_raw_data_dec': 9592, 'int_va_hex': '0x0040226c', 'int_va_dec
': 4203116, 'iat_raw_data_hex': '0x00002578', 'iat_raw_data_dec': 9592, 'iat_va_hex': '0x00402048', 'iat_va_dec': 4202568}, {'function_index': 11, 'import_type': 'Name import', 'hint_value': 363, 'function_info': '_XcptFilter', 'status
': 'Existing function forwarding', 'int_raw_data_hex': '0x00002452', 'int_raw_data_dec': 9298, 'int_va_hex': '0x00402270', 'int_va_dec': 4203120, 'iat_raw_data_hex': '0x00002452', 'iat_raw_data_dec': 9298, 'iat_va_hex': '0x0040204c', '
iat_va_dec': 4202572}, {'function_index': 12, 'import_type': 'Name import', 'hint_value': 413, 'function_info': '__crtGetShowWindowMode', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002460', 'int_raw_data_dec': 9
312, 'int_va_hex': '0x00402274', 'int_va_dec': 4203124, 'iat_raw_data_hex': '0x00002460', 'iat_raw_data_dec': 9312, 'iat_va_hex': '0x00402050', 'iat_va_dec': 4202576}, {'function_index': 13, 'import_type': 'Name import', 'hint_value':
535, 'function_info': '_amsg_exit', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000247a', 'int_raw_data_dec': 9338, 'int_va_hex': '0x00402278', 'int_va_dec': 4203128, 'iat_raw_data_hex': '0x0000247a', 'iat_raw_dat
a_dec': 9338, 'iat_va_hex': '0x00402054', 'iat_va_dec': 4202580}, {'function_index': 14, 'import_type': 'Name import', 'hint_value': 520, 'function_info': '__wgetmainargs', 'status': 'Existing function forwarding', 'int_raw_data_hex':
'0x00002488', 'int_raw_data_dec': 9352, 'int_va_hex': '0x0040227c', 'int_va_dec': 4203132, 'iat_raw_data_hex': '0x00002488', 'iat_raw_data_dec': 9352, 'iat_va_hex': '0x00402058', 'iat_va_dec': 4202584}, {'function_index': 15, 'import_t
ype': 'Name import', 'hint_value': 498, 'function_info': '__set_app_type', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000249a', 'int_raw_data_dec': 9370, 'int_va_hex': '0x00402280', 'int_va_dec': 4203136, 'iat_ra
w_data_hex': '0x0000249a', 'iat_raw_data_dec': 9370, 'iat_va_hex': '0x0040205c', 'iat_va_dec': 4202588}, {'function_index': 16, 'import_type': 'Name import', 'hint_value': 1614, 'function_info': 'exit', 'status': 'Existing function for
warding', 'int_raw_data_hex': '0x000024ac', 'int_raw_data_dec': 9388, 'int_va_hex': '0x00402284', 'int_va_dec': 4203140, 'iat_raw_data_hex': '0x000024ac', 'iat_raw_data_dec': 9388, 'iat_va_hex': '0x00402060', 'iat_va_dec': 4202592}, {'
function_index': 17, 'import_type': 'Name import', 'hint_value': 643, 'function_info': '_exit', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000024b4', 'int_raw_data_dec': 9396, 'int_va_hex': '0x00402288', 'int_va_d
ec': 4203144, 'iat_raw_data_hex': '0x000024b4', 'iat_raw_data_dec': 9396, 'iat_va_hex': '0x00402064', 'iat_va_dec': 4202596}, {'function_index': 18, 'import_type': 'Name import', 'hint_value': 559, 'function_info': '_cexit', 'status':
'Existing function forwarding', 'int_raw_data_hex': '0x000024bc', 'int_raw_data_dec': 9404, 'int_va_hex': '0x0040228c', 'int_va_dec': 4203148, 'iat_raw_data_hex': '0x000024bc', 'iat_raw_data_dec': 9404, 'iat_va_hex': '0x00402068', 'iat
_va_dec': 4202600}, {'function_index': 19, 'import_type': 'Name import', 'hint_value': 576, 'function_info': '_configthreadlocale', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000024c6', 'int_raw_data_dec': 9414, '
int_va_hex': '0x00402290', 'int_va_dec': 4203152, 'iat_raw_data_hex': '0x000024c6', 'iat_raw_data_dec': 9414, 'iat_va_hex': '0x0040206c', 'iat_va_dec': 4202604}, {'function_index': 20, 'import_type': 'Name import', 'hint_value': 500, '
function_info': '__setusermatherr', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000024dc', 'int_raw_data_dec': 9436, 'int_va_hex': '0x00402294', 'int_va_dec': 4203156, 'iat_raw_data_hex': '0x000024dc', 'iat_raw_dat
a_dec': 9436, 'iat_va_hex': '0x00402070', 'iat_va_dec': 4202608}, {'function_index': 21, 'import_type': 'Name import', 'hint_value': 781, 'function_info': '_initterm_e', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x
000024f0', 'int_raw_data_dec': 9456, 'int_va_hex': '0x00402298', 'int_va_dec': 4203160, 'iat_raw_data_hex': '0x000024f0', 'iat_raw_data_dec': 9456, 'iat_va_hex': '0x00402074', 'iat_va_dec': 4202612}, {'function_index': 22, 'import_type
': 'Name import', 'hint_value': 780, 'function_info': '_initterm', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000024fe', 'int_raw_data_dec': 9470, 'int_va_hex': '0x0040229c', 'int_va_dec': 4203164, 'iat_raw_data_h
ex': '0x000024fe', 'iat_raw_data_dec': 9470, 'iat_va_hex': '0x00402078', 'iat_va_dec': 4202616}, {'function_index': 23, 'import_type': 'Name import', 'hint_value': 1353, 'function_info': '_wcmdln', 'status': 'Existing function forwardi
ng', 'int_raw_data_hex': '0x0000250a', 'int_raw_data_dec': 9482, 'int_va_hex': '0x004022a0', 'int_va_dec': 4203168, 'iat_raw_data_hex': '0x0000250a', 'iat_raw_data_dec': 9482, 'iat_va_hex': '0x0040207c', 'iat_va_dec': 4202620}, {'funct
ion_index': 24, 'import_type': 'Name import', 'hint_value': 674, 'function_info': '_fmode', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x00002514', 'int_raw_data_dec': 9492, 'int_va_hex': '0x004022a4', 'int_va_dec':
 4203172, 'iat_raw_data_hex': '0x00002514', 'iat_raw_data_dec': 9492, 'iat_va_hex': '0x00402080', 'iat_va_dec': 4202624}, {'function_index': 25, 'import_type': 'Name import', 'hint_value': 575, 'function_info': '_commode', 'status': 'E
xisting function forwarding', 'int_raw_data_hex': '0x0000251e', 'int_raw_data_dec': 9502, 'int_va_hex': '0x004022a8', 'int_va_dec': 4203176, 'iat_raw_data_hex': '0x0000251e', 'iat_raw_data_dec': 9502, 'iat_va_hex': '0x00402084', 'iat_v
a_dec': 4202628}, {'function_index': 26, 'import_type': 'Name import', 'hint_value': 309, 'function_info': '?terminate@@YAXXZ', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000252a', 'int_raw_data_dec': 9514, 'int_
va_hex': '0x004022ac', 'int_va_dec': 4203180, 'iat_raw_data_hex': '0x0000252a', 'iat_raw_data_dec': 9514, 'iat_va_hex': '0x00402088', 'iat_va_dec': 4202632}, {'function_index': 27, 'import_type': 'Name import', 'hint_value': 425, 'func
tion_info': '__crtSetUnhandledExceptionFilter', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000253e', 'int_raw_data_dec': 9534, 'int_va_hex': '0x004022b0', 'int_va_dec': 4203184, 'iat_raw_data_hex': '0x0000253e',
'iat_raw_data_dec': 9534, 'iat_va_hex': '0x0040208c', 'iat_va_dec': 4202636}, {'function_index': 28, 'import_type': 'Name import', 'hint_value': 916, 'function_info': '_lock', 'status': 'Existing function forwarding', 'int_raw_data_hex
': '0x00002570', 'int_raw_data_dec': 9584, 'int_va_hex': '0x004022b4', 'int_va_dec': 4203188, 'iat_raw_data_hex': '0x00002570', 'iat_raw_data_dec': 9584, 'iat_va_hex': '0x00402090', 'iat_va_dec': 4202640}]}, {'dll_name': 'KERNEL32.dll'
, 'dll_index': 3, 'descriptor_rva_hex': '0x000011fc', 'descriptor_rva_dec': 4604, 'descriptor_foa_hex': '0x000005fc', 'descriptor_foa_dec': 1532, 'timestamp_hex': '0x00000000', 'timestamp_dec': 0, 'timestamp_desc': 'Unbound', 'forwarde
r_chain_hex': '0x00000000', 'forwarder_chain_dec': 0, 'forwarder_chain_desc': 'Presence forwarding', 'int_rva_hex': '0x00002224', 'int_rva_dec': 8740, 'int_foa_hex': '0x00001224', 'int_foa_dec': 4644, 'iat_rva_hex': '0x00002000', 'iat_
rva_dec': 8192, 'iat_foa_hex': '0x00001000', 'iat_foa_dec': 4096, 'function_count': 8, 'import_functions': [{'function_index': 1, 'import_type': 'Name import', 'hint_value': 877, 'function_info': 'IsProcessorFeaturePresent', 'status':
'Existing function forwarding', 'int_raw_data_hex': '0x000026c0', 'int_raw_data_dec': 9920, 'int_va_hex': '0x00402224', 'int_va_dec': 4203044, 'iat_raw_data_hex': '0x000026c0', 'iat_raw_data_dec': 9920, 'iat_va_hex': '0x00402000', 'iat
_va_dec': 4202496}, {'function_index': 2, 'import_type': 'Name import', 'hint_value': 871, 'function_info': 'IsDebuggerPresent', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x000026ac', 'int_raw_data_dec': 9900, 'int
_va_hex': '0x00402228', 'int_va_dec': 4203048, 'iat_raw_data_hex': '0x000026ac', 'iat_raw_data_dec': 9900, 'iat_va_hex': '0x00402004', 'iat_va_dec': 4202500}, {'function_index': 3, 'import_type': 'Name import', 'hint_value': 254, 'func
tion_info': 'DecodePointer', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000269c', 'int_raw_data_dec': 9884, 'int_va_hex': '0x0040222c', 'int_va_dec': 4203052, 'iat_raw_data_hex': '0x0000269c', 'iat_raw_data_dec':
 9884, 'iat_va_hex': '0x00402008', 'iat_va_dec': 4202504}, {'function_index': 4, 'import_type': 'Name import', 'hint_value': 726, 'function_info': 'GetSystemTimeAsFileTime', 'status': 'Existing function forwarding', 'int_raw_data_hex':
 '0x00002682', 'int_raw_data_dec': 9858, 'int_va_hex': '0x00402230', 'int_va_dec': 4203056, 'iat_raw_data_hex': '0x00002682', 'iat_raw_data_dec': 9858, 'iat_va_hex': '0x0040200c', 'iat_va_dec': 4202508}, {'function_index': 5, 'import_t
ype': 'Name import', 'hint_value': 526, 'function_info': 'GetCurrentThreadId', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000266c', 'int_raw_data_dec': 9836, 'int_va_hex': '0x00402234', 'int_va_dec': 4203060, 'ia
t_raw_data_hex': '0x0000266c', 'iat_raw_data_dec': 9836, 'iat_va_hex': '0x00402010', 'iat_va_dec': 4202512}, {'function_index': 6, 'import_type': 'Name import', 'hint_value': 522, 'function_info': 'GetCurrentProcessId', 'status': 'Exis
ting function forwarding', 'int_raw_data_hex': '0x00002656', 'int_raw_data_dec': 9814, 'int_va_hex': '0x00402238', 'int_va_dec': 4203064, 'iat_raw_data_hex': '0x00002656', 'iat_raw_data_dec': 9814, 'iat_va_hex': '0x00402014', 'iat_va_d
ec': 4202516}, {'function_index': 7, 'import_type': 'Name import', 'hint_value': 1069, 'function_info': 'QueryPerformanceCounter', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000263c', 'int_raw_data_dec': 9788, 'i
nt_va_hex': '0x0040223c', 'int_va_dec': 4203068, 'iat_raw_data_hex': '0x0000263c', 'iat_raw_data_dec': 9788, 'iat_va_hex': '0x00402018', 'iat_va_dec': 4202520}, {'function_index': 8, 'import_type': 'Name import', 'hint_value': 289, 'fu
nction_info': 'EncodePointer', 'status': 'Existing function forwarding', 'int_raw_data_hex': '0x0000262c', 'int_raw_data_dec': 9772, 'int_va_hex': '0x00402240', 'int_va_dec': 4203072, 'iat_raw_data_hex': '0x0000262c', 'iat_raw_data_dec
': 9772, 'iat_va_hex': '0x0040201c', 'iat_va_dec': 4202524}]}]}}
```

### show_export

For DLL files only. Parses exported functions, ordinals, RVAs and forwarder information to enumerate all public interfaces exposed by the dynamic link library.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        export = pe.show_export()
        print("[+] Export table information: ", export)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Export table information:  {'export_info': {'reason': 'Export table data not found (RVA of export table entry in data directory table is 0)', 'export_function_count': 0}, 'message': 'Export table data not found'}
```

### show_fix_reloc_page

Retrieve base metadata for all relocation table page blocks, counting total relocation blocks and their respective address ranges to analyze PE relocation mechanics.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        reloc_page = pe.show_fix_reloc_page()
        print("[+] Relocation pages: ", reloc_page)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Relocation pages:  {'fix_reloc_info': {'reason': 'No valid relocation table was found (relocation table entry RVA or size 0 in data directory table)', 'reloc_block_count': 0}, 'message': 'No valid relocation table found'}
```

### show_fix_reloc

Query detailed data for either all relocation entries or entries matching a specified RVA; inspect exact relocation addresses and fixup information for ASLR mechanism analysis.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)
    pe.open_file(r"e://win32.exe")

    try:
        # Pass "all" to retrieve every relocation entry
        reloc = pe.show_fix_reloc("all")
        print("[+] Full relocation data: ", reloc)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Full relocation data:  {'fix_reloc_filtered_info': {'reason': 'No valid relocation table was found (relocation table entry RVA or size 0 in data directory table)', 'requested_param': 'all', 'matched_block_count': 0}, 'message': 'No
 valid relocation table found'}
```

### show_resource

Parse three-level resource directories containing icons, strings, menus, version info and other embedded assets to extract all resource data packaged within the PE binary.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.show_resource()
        print("[+] Resource table information: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
Exception: 请求失败: 'utf-8' codec can't decode byte 0xa1 in position 471: invalid start byte
```

### rva_to_foa

Convert Relative Virtual Address (RVA) to File Offset Address (FOA), the most commonly used address conversion utility in PE reverse engineering.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.rva_to_foa("0x1000")
        print("[+] RVA to FOA conversion result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] RVA to FOA conversion result:  {'message': 'RVA converted FOA successfully', 'rva_to_foa_result': {'target_rva_hex': '0x00001000', 'target_rva_dec': 4096, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'section_total_co
unt': 4, 'section_scan_info': [{'section_index': 1, 'section_name': '.text', 'section_rva_start_hex': '0x00001000', 'section_rva_start_dec': 4096, 'section_rva_end_hex': '0x00001afc', 'section_rva_end_dec': 6908, 'section_foa_start_hex
': '0x00000400', 'section_foa_start_dec': 1024, 'is_target_section': True}], 'conversion_success': True, 'target_section_info': {'section_name': '.text', 'section_rva_start_hex': '0x00001000', 'section_rva_start_dec': 4096, 'section_rv
a_end_hex': '0x00001afc', 'section_rva_end_dec': 6908, 'section_foa_start_hex': '0x00000400', 'section_foa_start_dec': 1024, 'section_virtual_size_hex': '0x00000afc', 'section_virtual_size_dec': 2812, 'section_file_size_hex': '0x00000c
00', 'section_file_size_dec': 3072}, 'conversion_steps': [{'step': 1, 'description': 'Calculate VA (virtual address, auxiliary information)', 'formula': '', 'calculation': 'VA = 0x0x00400000 + 0x0x00001000 = 0x0x00401000'}, {'step': 2,
 'description': 'Calculate FOA (file offset address, core result)', 'formula': 'FOA=start of nodal FOA+(RVA - start of nodal RVA)', 'calculation': 'FOA = 0x0x00000400 + (0x0x00001000 - 0x0x00001000) = 0x0x00000400'}], 'final_result': {
'va_hex': '0x00401000', 'va_dec': 4198400, 'foa_hex': '0x00000400', 'foa_dec': 1024}}}
```

### foa_to_va

Convert File Offset Address (FOA) to in-memory Virtual Address (VA), enabling cross-referencing between disk layout and runtime memory layout.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.foa_to_va("0x800")
        print("[+] FOA to VA conversion result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] FOA to VA conversion result:  {'message': 'FOA converted VA successfully', 'foa_to_va_result': {'target_foa_hex': '0x00000800', 'target_foa_dec': 2048, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'file_total_size_hex
': '0x00003600', 'file_total_size_dec': 13824, 'section_total_count': 4, 'section_scan_info': [{'section_index': 1, 'section_name': '.text', 'section_foa_start_hex': '0x00000400', 'section_foa_start_dec': 1024, 'section_foa_end_hex': '
0x00000fff', 'section_foa_end_dec': 4095, 'section_rva_start_hex': '0x00001000', 'section_rva_start_dec': 4096, 'is_target_section': True}], 'conversion_success': True, 'target_section_info': {'section_name': '.text', 'section_foa_star
t_hex': '0x00000400', 'section_foa_start_dec': 1024, 'section_foa_end_hex': '0x00000fff', 'section_foa_end_dec': 4095, 'section_rva_start_hex': '0x00001000', 'section_rva_start_dec': 4096, 'section_file_size_hex': '0x00000c00', 'sectio
n_file_size_dec': 3072}, 'conversion_steps': [{'step': 1, 'description': 'Calculate RVA (relative virtual address)', 'formula': 'RVA=start of RVA+(FOA - start of FOA)', 'calculation': 'RVA = 0x0x00001000 + (0x0x00000800 - 0x0x00000400)
 = 0x0x00001400'}, {'step': 2, 'description': 'Calculate VA (virtual address, core result)', 'formula': 'VA=mirror base address+rva', 'calculation': 'VA = 0x0x00400000 + 0x0x00001400 = 0x0x00401400'}], 'final_result': {'rva_hex': '0x00
001400', 'rva_dec': 5120, 'va_hex': '0x00401400', 'va_dec': 4199424}}}
```

### va_to_foa

Directly convert runtime Virtual Address (VA) to disk File Offset Address (FOA), quickly locating binary data from execution-time memory addresses.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.va_to_foa("0x401000")
        print("[+] VA to FOA conversion result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] VA to FOA conversion result:  {'message': 'VA converted FOA successfully', 'va_to_foa_result': {'target_va_hex': '0x00401000', 'target_va_dec': 4198400, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'section_total_coun
t': 4, 'section_scan_info': [{'section_index': 1, 'section_name': '.text', 'section_va_start_hex': '0x00401000', 'section_va_start_dec': 4198400, 'section_va_end_hex': '0x00401afb', 'section_va_end_dec': 4201211, 'section_rva_start_hex
': '0x00001000', 'section_rva_start_dec': 4096, 'section_virtual_size_hex': '0x00000afc', 'section_virtual_size_dec': 2812, 'is_target_section': True}], 'conversion_success': True, 'target_section_info': {'section_name': '.text', 'sect
ion_rva_start_hex': '0x00001000', 'section_rva_start_dec': 4096, 'section_foa_start_hex': '0x00000400', 'section_foa_start_dec': 1024, 'section_virtual_size_hex': '0x00000afc', 'section_virtual_size_dec': 2812}, 'conversion_steps': [{'
step': 1, 'description': 'Calculate RVA (relative virtual address)', 'formula': 'RVA = VA - Mirror base address', 'calculation': 'RVA = 0x0x00401000 - 0x0x00400000 = 0x0x00001000'}, {'step': 2, 'description': 'Calculate FOA (file offse
t address)', 'formula': 'FOA=start of nodal FOA+(RVA - start of nodal RVA)', 'calculation': 'FOA = 0x0x00000400 + (0x0x00001000 - 0x0x00001000) = 0x0x00000400'}], 'final_result': {'rva_hex': '0x00001000', 'rva_dec': 4096, 'foa_hex': '0
x00000400', 'foa_dec': 1024}}}
```

### va_to_rva

Strip the image base from Virtual Address (VA) to calculate Relative Virtual Address (RVA), producing section-relative offsets for low-level reverse analysis.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.va_to_rva("0x401000")
        print("[+] VA to RVA conversion result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] VA to RVA conversion result:  {'message': 'VA successfully converted rva', 'va_to_rva_result': {'target_va_hex': '0x00401000', 'target_va_dec': 4198400, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'module_total_size_
hex': '0x00006000', 'module_total_size_dec': 24576, 'conversion_success': True, 'conversion_steps': [{'step': 1, 'description': 'Core conversion: calculate RVA (relative virtual address)', 'formula': 'RVA = VA - Mirror base address', '
calculation': 'RVA = 0x0x00401000 - 0x0x00400000 = 0x0x00001000'}], 'final_result': {'rva_hex': '0x00001000', 'rva_dec': 4096, 'rva_valid': True, 'validity_desc': 'RVA is within the effective range of the module (<total module size)'}}
}
```

### rva_to_va

Reconstruct full runtime Virtual Address (VA) by adding the image base to a Relative Virtual Address (RVA), used to restore actual in-memory execution addresses.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.rva_to_va("0x1000")
        print("[+] RVA to VA conversion result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] RVA to VA conversion result:  {'message': 'RVA converted VA successfully', 'rva_to_va_result': {'target_rva_hex': '0x00001000', 'target_rva_dec': 4096, 'image_base_hex': '0x00400000', 'image_base_dec': 4194304, 'module_total_size_h
ex': '0x00006000', 'module_total_size_dec': 24576, 'section_total_count': 4, 'section_check_info': [{'section_index': 1, 'section_name': '.text', 'section_rva_start_hex': '0x00001000', 'section_rva_start_dec': 4096, 'section_rva_end_he
x': '0x00001afc', 'section_rva_end_dec': 6908, 'is_rva_in_section': True}], 'conversion_success': True, 'conversion_steps': [{'step': 1, 'description': 'Core conversion: calculate VA (virtual address)', 'formula': 'VA = Mirror base add
ress + RVA', 'calculation': 'VA = 0x0x00400000 + 0x0x00001000 = 0x0x00401000'}], 'section_check_result': {'is_rva_in_valid_section': True, 'valid_section_name': '.text', 'check_desc': 'RVA is within the valid section, and VA address is
 valid'}, 'final_result': {'va_hex': '0x00401000', 'va_dec': 4198400, 'va_validity_desc': 'VA valid (RVA is within the valid section)'}}}
```

### get_hex_ascii

Read machine code hexadecimal bytes and corresponding ASCII characters within a specified FOA range, formatting binary raw data for static inspection.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        # Read 0x10 bytes starting at file offset 0
        hex_data = pe.get_hex_ascii(0, 0x10)
        print("[+] Hexadecimal binary data: ", hex_data)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Hexadecimal binary data:  {'message': 'Successfully read file hex/ASCII', 'hex_ascii_info': {'file_path': 'e://win32.exe', 'file_total_size_hex': '0x00003600', 'file_total_size_dec': 13824, 'read_range': {'requested_start_hex': '0x
00000000', 'requested_start_dec': 0, 'requested_len_hex': '0x00000010', 'requested_len_dec': 16, 'actual_start_hex': '0x00000000', 'actual_start_dec': 0, 'actual_end_hex': '0x0000000f', 'actual_end_dec': 15, 'actual_len_hex': '0x000000
10', 'actual_len_dec': 16}, 'statistics': {'total_read_bytes': 16, 'total_lines': 1}, 'hex_ascii_data': [{'line_offset_hex': '0x00000000', 'line_offset_dec': 0, 'hex_array': ['4D', '5A', '90', '00', '03', '00', '00', '00', '04', '00',
'00', '00', 'FF', 'FF', '00', '00'], 'ascii_str': 'MZ..............'}]}}
```

### search_signature

Search for machine code byte signatures within a defined file range; supports wildcard `??` for partial pattern matching, commonly used for vulnerability and code signature detection.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        sig = pe.search_signature(0, 0x10000, "55 8B ?? EC")
        print("[+] Signature match results: ", sig)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Signature match results:  {'message': 'Signature search completed, no matching results found', 'signature_search_info': {'file_path': 'e://win32.exe', 'signature_config': {'signature_str': '55 8B ?? EC', 'signature_len_bytes': 4},
'file_total_size_hex': '0x00003600', 'file_total_size_dec': 13824, 'search_range': {'requested_start_hex': '0x00000000', 'requested_start_dec': 0, 'requested_len_hex': '0x00010000', 'requested_len_dec': 65536, 'actual_start_hex': '0x00
000000', 'actual_start_dec': 0, 'actual_end_hex': '0x000035ff', 'actual_end_dec': 13823, 'actual_len_hex': '0x00003600', 'actual_len_dec': 13824, 'warning': 'Search range exceeds file size, automatically truncated to: start=0, end=1382
3, length=13824'}, 'match_result': {'match_count': 0, 'matches': []}, 'statistics': {'total_searched_bytes': 13824, 'total_matches': 0}}}
```

### search_string

Perform exact lookup of ASCII plaintext strings inside the PE binary, quickly locating hardcoded paths, messages, function names and other embedded text literals.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        str_res = pe.search_string(0, 0x10000, "CreateFileA")
        print("[+] String match results: ", str_res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] String match results:  {'message': 'String search completed, no matching results found', 'string_search_info': {'file_path': 'e://win32.exe', 'search_config': {'target_string': 'CreateFileA', 'target_string_len_bytes': 11, 'request
ed_start_foa_hex': '0x00000000', 'requested_start_foa_dec': 0, 'requested_search_len_hex': '0x00010000', 'requested_search_len_dec': 65536}, 'file_total_size_hex': '0x00003600', 'file_total_size_dec': 13824, 'actual_search_range': {'ac
tual_start_foa_hex': '0x00000000', 'actual_start_foa_dec': 0, 'actual_end_foa_hex': '0x000035ff', 'actual_end_foa_dec': 13823, 'actual_search_len_hex': '0x00003600', 'actual_search_len_dec': 13824, 'warning': 'Search range exceeds file
 size, automatically truncated to: start FOA=0, end FOA=13823, actual search length=13824'}, 'match_result': {'match_count': 0, 'match_details': []}, 'statistics': {'total_searched_bytes': 13824, 'total_matches': 0}}}
```

### get_module_status

Inspect memory protection and compilation security flags including ASLR, DEP, CFG and compatibility modes to audit the binary's exploit mitigation features.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        status = pe.get_module_status()
        print("[+] Module security mitigation status: ", status)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Module security mitigation status:  {'message': 'Successfully parsed module properties and protection methods', 'module_status_info': {'file_path': 'e://win32.exe', 'basic_properties': {'file_type': 'Executable file (EXE)', 'machin
e_architecture': 'x86 (32-bit)', 'subsystem_type': 'Graphical user interface application (GUI)', 'linker_version': '0.0'}, 'security_features': {'aslr_enabled': False, 'aslr_description': 'Disabled', 'high_entropy_aslr_enabled': False,
 'high_entropy_aslr_description': 'Disabled', 'dep_enabled': False, 'dep_description': 'Incompatible (may allow data execution)', 'cfg_enabled': False, 'cfg_description': 'Disabled', 'force_integrity_enabled': False, 'force_integrity_d
escription': 'Disabled', 'seh_enabled': True, 'seh_description': 'Allowed (supports structured exception handling)', 'has_digital_certificate': False, 'cert_description': 'Does not exist'}, 'other_features': {'terminal_server_aware': T
rue, 'ts_aware_description': 'Yes (compatible with terminal services environment)', 'uac_virtualization_enabled': True, 'uac_virtualization_description': 'Enabled', 'isolation_enabled': False, 'isolation_description': 'Disabled', 'has_
debug_info': False, 'debug_info_description': 'Does not exist'}}}
```

### get_process_address

Simulate native Win32 `LoadLibrary` + `GetProcAddress` logic to retrieve runtime memory address and RVA of an exported function from a target DLL.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        addr = pe.get_process_address("KERNEL32.dll", "CreateFileA")
        print("[+] Function address information: ", addr)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Function address information:  {'get_process_address_info': {'requested_dll_name': 'KERNEL32.dll', 'requested_function_name': 'CreateFileA', 'success': True, 'success_data': {'dll_info': {'dll_name': 'KERNEL32.dll', 'dll_base_va_he
x': '0x75b70000', 'dll_base_va_dec': 1974927360}, 'function_info': {'function_name': 'CreateFileA', 'function_va_hex': '0x75b93d50', 'function_va_dec': 1975074128, 'function_rva_hex': '0x00023d50', 'function_rva_dec': 146768}}}, 'messa
ge': 'Successfully got DLL function address'}
```

### disassemble_code

Disassemble x86-32 machine code from a specified file offset range powered by the Capstone engine to inspect assembly instruction logic.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        disasm = pe.disassemble_code("0x1000", 0x200)
        print("[+] Disassembly output: ", disasm)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Disassembly output:  {'message': 'Disassembly completed, instructions successfully identified', 'disasm_result': {'disasm_config': {'file_path': 'e://win32.exe', 'start_foa_hex': '0x00001000', 'start_foa_dec': 4096, 'disasm_len_hex
': '0x00000200', 'disasm_len_dec': 512, 'capstone_info': 'Architecture: x86, Mode: 32-bit'}, 'disasm_instructions': [{'opcode_size_bytes': 3, 'opstring_size_chars': 21, 'real_foa_hex': '0x00001000', 'real_foa_dec': 4096, 'opcode_hex_ar
ray': ['C0', '26', '00'], 'disassembled_instruction': 'shl byte ptr [esi], 0'}, {'opcode_size_bytes': 7, 'opstring_size_chars': 35, 'real_foa_hex': '0x00001003', 'real_foa_dec': 4099, 'opcode_hex_array': ['00', 'AC', '26', '00', '00',
'9C', '26'], 'disassembled_instruction': 'add byte ptr [esi + 0x269c0000], ch'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000100a', 'real_foa_dec': 4106, 'opcode_hex_array': ['00', '00'], 'disassembled_in
struction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 3, 'opstring_size_chars': 21, 'real_foa_hex': '0x0000100c', 'real_foa_dec': 4108, 'opcode_hex_array': ['82', '26', '00'], 'disassembled_instruction': 'and byte ptr [esi], 0'}
, {'opcode_size_bytes': 4, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000100f', 'real_foa_dec': 4111, 'opcode_hex_array': ['00', '6C', '26', '00'], 'disassembled_instruction': 'add byte ptr [esi], ch'}, {'opcode_size_bytes': 3, 'op
string_size_chars': 29, 'real_foa_hex': '0x00001013', 'real_foa_dec': 4115, 'opcode_hex_array': ['00', '56', '26'], 'disassembled_instruction': 'add byte ptr [esi + 0x26], dl'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real
_foa_hex': '0x00001016', 'real_foa_dec': 4118, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 12, 'real_foa_hex': '0x00001018', 'real_foa_dec': 4
120, 'opcode_hex_array': ['3C', '26'], 'disassembled_instruction': 'cmp al, 0x26'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000101a', 'real_foa_dec': 4122, 'opcode_hex_array': ['00', '00'], 'disassembled
_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 12, 'real_foa_hex': '0x0000101c', 'real_foa_dec': 4124, 'opcode_hex_array': ['2C', '26'], 'disassembled_instruction': 'sub al, 0x26'}, {'opcode_s
ize_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000101e', 'real_foa_dec': 4126, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22,
'real_foa_hex': '0x00001020', 'real_foa_dec': 4128, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x00001022', 'real_foa_de
c': 4130, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 12, 'real_foa_hex': '0x00001024', 'real_foa_dec': 4132, 'opcode_hex_array': ['14', '26']
, 'disassembled_instruction': 'adc al, 0x26'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x00001026', 'real_foa_dec': 4134, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], a
l'}, {'opcode_size_bytes': 1, 'opstring_size_chars': 4, 'real_foa_hex': '0x00001028', 'real_foa_dec': 4136, 'opcode_hex_array': ['FA'], 'disassembled_instruction': 'cli '}, {'opcode_size_bytes': 5, 'opstring_size_chars': 19, 'real_foa_
hex': '0x00001029', 'real_foa_dec': 4137, 'opcode_hex_array': ['25', '00', '00', 'E4', '25'], 'disassembled_instruction': 'and eax, 0x25e40000'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000102e', 'real_f
oa_dec': 4142, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 3, 'opstring_size_chars': 9, 'real_foa_hex': '0x00001030', 'real_foa_dec': 4144, 'opcode_hex_array': ['CA', '
25', '00'], 'disassembled_instruction': 'retf 0x25'}, {'opcode_size_bytes': 6, 'opstring_size_chars': 35, 'real_foa_hex': '0x00001033', 'real_foa_dec': 4147, 'opcode_hex_array': ['00', 'BA', '25', '00', '00', 'A8'], 'disassembled_instr
uction': 'add byte ptr [edx - 0x57ffffdb], bh'}, {'opcode_size_bytes': 5, 'opstring_size_chars': 19, 'real_foa_hex': '0x00001039', 'real_foa_dec': 4153, 'opcode_hex_array': ['25', '00', '00', '9E', '25'], 'disassembled_instruction': 'a
nd eax, 0x259e0000'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000103e', 'real_foa_dec': 4158, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes'
: 1, 'opstring_size_chars': 4, 'real_foa_hex': '0x00001040', 'real_foa_dec': 4160, 'opcode_hex_array': ['90'], 'disassembled_instruction': 'nop '}, {'opcode_size_bytes': 5, 'opstring_size_chars': 19, 'real_foa_hex': '0x00001041', 'real
_foa_dec': 4161, 'opcode_hex_array': ['25', '00', '00', '82', '25'], 'disassembled_instruction': 'and eax, 0x25820000'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x00001046', 'real_foa_dec': 4166, 'opcode_he
x_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 7, 'real_foa_hex': '0x00001048', 'real_foa_dec': 4168, 'opcode_hex_array': ['78', '25'], 'disassembled_instr
uction': 'js 0x6f'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000104a', 'real_foa_dec': 4170, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes':
 1, 'opstring_size_chars': 8, 'real_foa_hex': '0x0000104c', 'real_foa_dec': 4172, 'opcode_hex_array': ['52'], 'disassembled_instruction': 'push edx'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 9, 'real_foa_hex': '0x0000104d', 're
al_foa_dec': 4173, 'opcode_hex_array': ['24', '00'], 'disassembled_instruction': 'and al, 0'}, {'opcode_size_bytes': 3, 'opstring_size_chars': 29, 'real_foa_hex': '0x0000104f', 'real_foa_dec': 4175, 'opcode_hex_array': ['00', '60', '24
'], 'disassembled_instruction': 'add byte ptr [eax + 0x24], ah'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x00001052', 'real_foa_dec': 4178, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'ad
d byte ptr [eax], al'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 7, 'real_foa_hex': '0x00001054', 'real_foa_dec': 4180, 'opcode_hex_array': ['7A', '24'], 'disassembled_instruction': 'jp 0x7a'}, {'opcode_size_bytes': 2, 'opstring
_size_chars': 22, 'real_foa_hex': '0x00001056', 'real_foa_dec': 4182, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction': 'add byte ptr [eax], al'}, {'opcode_size_bytes': 3, 'opstring_size_chars': 28, 'real_foa_hex': '0x00001
058', 'real_foa_dec': 4184, 'opcode_hex_array': ['88', '24', '00'], 'disassembled_instruction': 'mov byte ptr [eax + eax], ah'}, {'opcode_size_bytes': 6, 'opstring_size_chars': 35, 'real_foa_hex': '0x0000105b', 'real_foa_dec': 4187, 'o
pcode_hex_array': ['00', '9A', '24', '00', '00', 'AC'], 'disassembled_instruction': 'add byte ptr [edx - 0x53ffffdc], bl'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 9, 'real_foa_hex': '0x00001061', 'real_foa_dec': 4193, 'opcode_
hex_array': ['24', '00'], 'disassembled_instruction': 'and al, 0'}, {'opcode_size_bytes': 7, 'opstring_size_chars': 35, 'real_foa_hex': '0x00001063', 'real_foa_dec': 4195, 'opcode_hex_array': ['00', 'B4', '24', '00', '00', 'BC', '24'],
 'disassembled_instruction': 'add byte ptr [esp + 0x24bc0000], dh'}, {'opcode_size_bytes': 2, 'opstring_size_chars': 22, 'real_foa_hex': '0x0000106a', 'real_foa_dec': 4202, 'opcode_hex_array': ['00', '00'], 'disassembled_instruction':
'add byte ptr [eax], al'}], 'statistics': {'total_instructions': 38, 'total_bytes_disassembled': 512}}}

```

### add_calculator

Unsigned DWORD hexadecimal addition utility optimized for PE address and size arithmetic; automatically parses both decimal and hexadecimal input formats.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.add_calculator("0x400000", "0x1000")
        print("[+] Hex addition result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Hex addition result:  {'add_calculator': {'input_params': {'x_hex': '0x400000', 'x_dec': 4194304, 'y_hex': '0x1000', 'y_dec': 4096}, 'calculation_result': {'hex': '0x00401000', 'dec': 4198400, 'oct': '20010000', 'bin': '10000000001
000000000000', 'expression': '0x00400000 + 0x00001000 = 0x00401000'}}, 'message': 'Addition calculation successful'}
```

### sub_calculator

Unsigned DWORD hexadecimal subtraction utility; negative results wrap modulo 2^32, designed for calculating address offsets and differences in PE structures.

```python
from peview_client import *

if __name__ == "__main__":
    cfg = Config("127.0.0.1", 8000)
    if not cfg.is_server_available():
        print("[-] Failed to connect to server")
        exit(0)

    pe = PE(cfg)

    try:
        pe.open_file(r"e://win32.exe")
        res = pe.sub_calculator(0x401000, 0x1000)
        print("[+] Hex subtraction result: ", res)
    finally:
        pe.close_file()
```

The output of the running result is a JSON string, as shown below:

```bash
[+] Hex subtraction result:  {'sub_calculator': {'input_params': {'x_hex': '0x401000', 'x_dec': 4198400, 'y_hex': '0x1000', 'y_dec': 4096}, 'calculation_result': {'hex': '0x00400000', 'dec': 4194304, 'oct': '20000000', 'bin': '10000000
000000000000000', 'expression': '0x00401000 - 0x00001000 = 0x00400000', 'note': 'Subtraction is based on DWORD unsigned calculation; negative numbers are automatically converted to modulo 2^32 values'}}, 'message': 'Subtraction calcula
tion successful'}
```
