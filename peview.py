# -*- coding: utf8 -*-
import pefile
import os
import binascii
from datetime import datetime, timedelta

DOS_HEADER_Description = [
    'Signature',
    'Bytes on Last Page of File',
    'Pages in File',
    'Relocations',
    'Size of Header in Paragraphs',
    'Minimum Extra Paragraphs',
    'Maximum Extra Paragraphs',
    'Initial (relative) SS',
    'Initial SP',
    'Checksum',
    'Initial IP',
    'Initial (relative) CS',
    'Offset to Relocation Table',
    'Overlay Number',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'OEM Identifier',
    'OEM Information',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Reserved',
    'Offset to New EXE Header'
]

machine_values = [
    ("IMAGE_FILE_MACHINE_UNKNOWN", 0x0),
    ("IMAGE_FILE_MACHINE_I386", 0x014C),
    ("IMAGE_FILE_MACHINE_R3000", 0x0162),
    ("IMAGE_FILE_MACHINE_R4000", 0x0166),
    ("IMAGE_FILE_MACHINE_R10000", 0x0168),
    ("IMAGE_FILE_MACHINE_WCEMIPSV2", 0x0169),
    ("IMAGE_FILE_MACHINE_ALPHA", 0x0184),
    ("IMAGE_FILE_MACHINE_SH3", 0x01A2),
    ("IMAGE_FILE_MACHINE_SH3DSP", 0x01A3),
    ("IMAGE_FILE_MACHINE_SH3E", 0x01A4),
    ("IMAGE_FILE_MACHINE_SH4", 0x01A6),
    ("IMAGE_FILE_MACHINE_SH5", 0x01A8),
    ("IMAGE_FILE_MACHINE_ARM", 0x01C0),
    ("IMAGE_FILE_MACHINE_THUMB", 0x01C2),
    ("IMAGE_FILE_MACHINE_ARMNT", 0x01C4),
    ("IMAGE_FILE_MACHINE_AM33", 0x01D3),
    ("IMAGE_FILE_MACHINE_POWERPC", 0x01F0),
    ("IMAGE_FILE_MACHINE_POWERPCFP", 0x01F1),
    ("IMAGE_FILE_MACHINE_IA64", 0x0200),
    ("IMAGE_FILE_MACHINE_MIPS16", 0x0266),
    ("IMAGE_FILE_MACHINE_ALPHA64", 0x0284),
    ("IMAGE_FILE_MACHINE_AXP64", 0x0284),
    ("IMAGE_FILE_MACHINE_MIPSFPU", 0x0366),
    ("IMAGE_FILE_MACHINE_MIPSFPU16", 0x0466),
    ("IMAGE_FILE_MACHINE_TRICORE", 0x0520),
    ("IMAGE_FILE_MACHINE_CEF", 0x0CEF),
    ("IMAGE_FILE_MACHINE_EBC", 0x0EBC),
    ("IMAGE_FILE_MACHINE_RISCV32", 0x5032),
    ("IMAGE_FILE_MACHINE_RISCV64", 0x5064),
    ("IMAGE_FILE_MACHINE_RISCV128", 0x5128),
    ("IMAGE_FILE_MACHINE_LOONGARCH32", 0x6232),
    ("IMAGE_FILE_MACHINE_LOONGARCH64", 0x6264),
    ("IMAGE_FILE_MACHINE_AMD64", 0x8664),
    ("IMAGE_FILE_MACHINE_M32R", 0x9041),
    ("IMAGE_FILE_MACHINE_ARM64", 0xAA64),
    ("IMAGE_FILE_MACHINE_CEE", 0xC0EE),
]

file_header_flags = [
    ("IMAGE_FILE_RELOCS_STRIPPED", 0x0001),
    ("IMAGE_FILE_EXECUTABLE_IMAGE", 0x0002),
    ("IMAGE_FILE_LINE_NUMS_STRIPPED", 0x0004),
    ("IMAGE_FILE_LOCAL_SYMS_STRIPPED", 0x0008),
    ("IMAGE_FILE_AGGRESIVE_WS_TRIM", 0x0010),
    ("IMAGE_FILE_LARGE_ADDRESS_AWARE", 0x0020),
    ("IMAGE_FILE_16BIT_MACHINE", 0x0040),
    ("IMAGE_FILE_BYTES_REVERSED_LO", 0x0080),
    ("IMAGE_FILE_32BIT_MACHINE", 0x0100),
    ("IMAGE_FILE_DEBUG_STRIPPED", 0x0200),
    ("IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP", 0x0400),
    ("IMAGE_FILE_NET_RUN_FROM_SWAP", 0x0800),
    ("IMAGE_FILE_SYSTEM", 0x1000),
    ("IMAGE_FILE_DLL", 0x2000),
    ("IMAGE_FILE_UP_SYSTEM_ONLY", 0x4000),
    ("IMAGE_FILE_BYTES_REVERSED_HI", 0x8000),
]

directory_entry_types = {
    'IMAGE_DIRECTORY_ENTRY_EXPORT': 'EXPORT Table',
    'IMAGE_DIRECTORY_ENTRY_IMPORT': 'IMPORT Table',
    'IMAGE_DIRECTORY_ENTRY_RESOURCE': 'RESOURCE Table',
    'IMAGE_DIRECTORY_ENTRY_EXCEPTION': 'EXCEPTION Table',
    'IMAGE_DIRECTORY_ENTRY_SECURITY': 'CERTIFICATE Table',
    'IMAGE_DIRECTORY_ENTRY_BASERELOC': 'BASE RELOCATION Table',
    'IMAGE_DIRECTORY_ENTRY_DEBUG': 'DEBUG Directory',
    'IMAGE_DIRECTORY_ENTRY_COPYRIGHT': 'Architecture Specific Data',
    'IMAGE_DIRECTORY_ENTRY_GLOBALPTR': 'GLOBAL POINTER Register',
    'IMAGE_DIRECTORY_ENTRY_TLS': 'TLS Table',
    'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG': 'LOAD CONFIGURATION',
    'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT': 'BOUND IMPORT Table',
    'IMAGE_DIRECTORY_ENTRY_IAT': 'IMPORT Address Table',
    'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT': 'DELAY IMPORT Descriptors',
    'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR': 'CLI Header',
    'IMAGE_DIRECTORY_ENTRY_RESERVED':'Reserved Directory'
}

subsystem_values = [
    ("IMAGE_SUBSYSTEM_UNKNOWN", 0),
    ("IMAGE_SUBSYSTEM_NATIVE", 1),
    ("IMAGE_SUBSYSTEM_WINDOWS_GUI", 2),
    ("IMAGE_SUBSYSTEM_WINDOWS_CUI", 3),
    ("IMAGE_SUBSYSTEM_OS2_CUI", 5),
    ("IMAGE_SUBSYSTEM_POSIX_CUI", 7),
    ("IMAGE_SUBSYSTEM_NATIVE_WINDOWS", 8),
    ("IMAGE_SUBSYSTEM_WINDOWS_CE_GUI", 9),
    ("IMAGE_SUBSYSTEM_EFI_APPLICATION", 10),
    ("IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER", 11),
    ("IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER", 12),
    ("IMAGE_SUBSYSTEM_EFI_ROM", 13),
    ("IMAGE_SUBSYSTEM_XBOX", 14),
    ("IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION", 16),
]

section_header_flags = [
    ("IMAGE_SCN_TYPE_REG", 0x00000000),
    ("IMAGE_SCN_TYPE_DSECT", 0x00000001),
    ("IMAGE_SCN_TYPE_NOLOAD", 0x00000002),
    ("IMAGE_SCN_TYPE_GROUP", 0x00000004),
    ("IMAGE_SCN_TYPE_NO_PAD", 0x00000008),
    ("IMAGE_SCN_TYPE_COPY", 0x00000010),
    ("IMAGE_SCN_CNT_CODE", 0x00000020),
    ("IMAGE_SCN_CNT_INITIALIZED_DATA", 0x00000040),
    ("IMAGE_SCN_CNT_UNINITIALIZED_DATA", 0x00000080),
    ("IMAGE_SCN_LNK_OTHER", 0x00000100),
    ("IMAGE_SCN_LNK_INFO", 0x00000200),
    ("IMAGE_SCN_LNK_OVER", 0x00000400),
    ("IMAGE_SCN_LNK_REMOVE", 0x00000800),
    ("IMAGE_SCN_LNK_COMDAT", 0x00001000),
    ("IMAGE_SCN_MEM_PROTECTED", 0x00004000),
    ("IMAGE_SCN_NO_DEFER_SPEC_EXC", 0x00004000),
    ("IMAGE_SCN_GPREL", 0x00008000),
    ("IMAGE_SCN_MEM_FARDATA", 0x00008000),
    ("IMAGE_SCN_MEM_SYSHEAP", 0x00010000),
    ("IMAGE_SCN_MEM_PURGEABLE", 0x00020000),
    ("IMAGE_SCN_MEM_16BIT", 0x00020000),
    ("IMAGE_SCN_MEM_LOCKED", 0x00040000),
    ("IMAGE_SCN_MEM_PRELOAD", 0x00080000),
    ("IMAGE_SCN_ALIGN_1BYTES", 0x00100000),
    ("IMAGE_SCN_ALIGN_2BYTES", 0x00200000),
    ("IMAGE_SCN_ALIGN_4BYTES", 0x00300000),
    ("IMAGE_SCN_ALIGN_8BYTES", 0x00400000),
    ("IMAGE_SCN_ALIGN_16BYTES", 0x00500000),
    ("IMAGE_SCN_ALIGN_32BYTES", 0x00600000),
    ("IMAGE_SCN_ALIGN_64BYTES", 0x00700000),
    ("IMAGE_SCN_ALIGN_128BYTES", 0x00800000),
    ("IMAGE_SCN_ALIGN_256BYTES", 0x00900000),
    ("IMAGE_SCN_ALIGN_512BYTES", 0x00A00000),
    ("IMAGE_SCN_ALIGN_1024BYTES", 0x00B00000),
    ("IMAGE_SCN_ALIGN_2048BYTES", 0x00C00000),
    ("IMAGE_SCN_ALIGN_4096BYTES", 0x00D00000),
    ("IMAGE_SCN_ALIGN_8192BYTES", 0x00E00000),
    ("IMAGE_SCN_ALIGN_MASK", 0x00F00000),
    ("IMAGE_SCN_LNK_NRELOC_OVFL", 0x01000000),
    ("IMAGE_SCN_MEM_DISCARDABLE", 0x02000000),
    ("IMAGE_SCN_MEM_NOT_CACHED", 0x04000000),
    ("IMAGE_SCN_MEM_NOT_PAGED", 0x08000000),
    ("IMAGE_SCN_MEM_SHARED", 0x10000000),
    ("IMAGE_SCN_MEM_EXECUTE", 0x20000000),
    ("IMAGE_SCN_MEM_READ", 0x40000000),
    ("IMAGE_SCN_MEM_WRITE", 0x80000000),
]

def select_menu():
    print("="*77)
    print("""
    1. IMAGE_DOS_HEADER
    2. DOS_Stub
    3. IMAGE_NT_HEADERS
    4. NT_Signature
    5. IMAGE_FILE_HEADER
    6. IMAGE_OPTIONAL_HEADER
    7. IMAGE_SECTION_HEADERS
    8. View Section List
    """)  # 7번 함수 안에 섹션을 출력할 수 있는 기능 구현

def print_subsystem_message(value):
    for message in subsystem_values:
        if(message[1]) == value:
            return message[0]


def print_DOS_HEADER(pe, filename):
    print("-" * 70)
    print("[IMAGE_DOS_HEADER]")
    print("pFile" + "   |   " + "Data" + "   |" + "Description" + " " * 17 + "|" + "Value")

    with open(filename, 'rb') as f:
        data = f.read()
        offset = 0x00000000
        num = int(0)
        dos_header = data[0:60]

        for i in range(0, len(dos_header), 2):
            raw_data = dos_header[i:i+2]
            hex_values = ''.join([binascii.hexlify(raw_data[i:i+1]).decode('utf-8') for i in range(len(raw_data)-1, -1, -1)])
            if(i == 0):
                print(f"{offset:08X}    {hex_values.upper()}    {DOS_HEADER_Description[num]}                    IMAGE_DOS_SIGNATURE MZ")
            else:
                print(f"{offset:08X}    {hex_values.upper()}    {DOS_HEADER_Description[num]}")

            offset += 2
            num+=1

        raw_data = data[60:64]
        hex_values = ''.join([binascii.hexlify(raw_data[i:i+1]).decode('utf-8') for i in range(len(raw_data)-1, -1, -1)])
        print(f"{offset:08X}  {hex_values.upper()}  {DOS_HEADER_Description[num]}")

        print("-" * 70, "\n")


def print_DOS_Stub(pe):
    print("[MS-DOS Stub Program]")
    pe_signature_offset = pe.NT_HEADERS.get_field_absolute_offset('Signature')
    dos_stub = pe.get_memory_mapped_image()[64:pe_signature_offset]
    print(f"  pFile |                     Raw Data                     |Value")
    offset = 0x40

    for i in range(0, len(dos_stub), 16):
        raw_data = dos_stub[i:i+16]
        hex_values = ' '.join([binascii.hexlify(raw_data[i:i+1]).decode('utf-8') for i in range(len(raw_data))])
        ascii_values = ''.join(chr(raw_data[i]) if 31 < raw_data[i] < 127 else '.' for i in range(len(raw_data)))
        print(f'{offset:08X}  {hex_values:<48}  {ascii_values}')
        offset += 16


def print_NT_HEADERS(pe, filename):
    print("[IMAGE_NT_HEADERS]")
    print(f"  pFile |                     Raw Data                     |Value")

    section_offset = pe.sections[0].Name

    with open(filename, 'rb') as f:
        data = f.read()
        section_offset = data.find(section_offset)

    pe_signature_offset = pe.NT_HEADERS.get_field_absolute_offset('Signature')
    nt_header = pe.get_memory_mapped_image()[pe_signature_offset:section_offset]
    offset = pe_signature_offset

    for i in range(0, len(nt_header), 16):
        raw_data = nt_header[i:i+16]
        hex_values = ' '.join([binascii.hexlify(raw_data[i:i+1]).decode('utf-8') for i in range(len(raw_data))])
        ascii_values = ''.join(chr(raw_data[i]) if 31 < raw_data[i] < 127 else '.' for i in range(len(raw_data)))
        print(f'{offset:08X}  {hex_values:<48}  {ascii_values}')
        offset += 16


def print_NT_Signature(pe):
    print("[Signature]")
    print(f"  pFile   |   Data   |Description   |Value")
    pe_signature_offset = pe.NT_HEADERS.get_field_absolute_offset('Signature')
    pe_signature = pe.NT_HEADERS.Signature
    print(f'{pe_signature_offset:08X}    {pe_signature:08X}  Signature      IMAGE_NT_SIGNATURE PE')


def print_FILE_HEADER(pe):
    print("[IMAGE_FILE_HEADER]")
    print(f"  pFile   |   Data   |Description            |Value")

    file_header_machine = pe.FILE_HEADER.Machine
    file_header_offset = pe.NT_HEADERS.get_field_absolute_offset('Signature') + 4

    for message in machine_values:
        if(file_header_machine == message[1]):
            Value = message[0]

    print(f"{file_header_offset:08X}      {file_header_machine:04X}    Machine                 {Value}")
    file_header_offset += 2
    file_header_sectionNum = pe.FILE_HEADER.NumberOfSections
    print(f"{file_header_offset:08X}      {file_header_sectionNum:04X}    Number of Sections")
    file_header_offset += 2
    file_header_timestamp = pe.FILE_HEADER.TimeDateStamp
    print(f"{file_header_offset:08X}    {file_header_timestamp:08X}  Time Date Stamp         {datetime.fromtimestamp(file_header_timestamp)-timedelta(hours=9)} UTC")
    file_header_offset += 4
    file_header_PointerToSymbolTable = pe.FILE_HEADER.PointerToSymbolTable
    print(f"{file_header_offset:08X}    {file_header_PointerToSymbolTable:08X}  Pointer to Symbol Table")
    file_header_offset += 4
    file_header_symbolNum = pe.FILE_HEADER.NumberOfSymbols
    print(f"{file_header_offset:08X}    {file_header_symbolNum:08X}  Number of Symbols")
    file_header_offset += 4
    file_header_optional_header = pe.FILE_HEADER.SizeOfOptionalHeader
    print(f"{file_header_offset:08X}      {file_header_optional_header:04X}    Size of Optional Header")
    file_header_offset += 2
    file_header_characteristics = pe.FILE_HEADER.Characteristics
    print(f"{file_header_offset:08X}      {file_header_characteristics:04X}    Characteristics")

    for characteristic, value in file_header_flags:
        if file_header_characteristics & value:
            print(" " * 22 + f"{value:04X}      {characteristic}")


def print_OPTIONAL_HEADER(pe):
    print("[IMAGE_OPTIONAL_HEADER]")
    print(f"  pFile   |   Data   |Description            |Value")
    optional_header_offset = pe.NT_HEADERS.get_field_absolute_offset('Signature') + 24
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.Magic:04X}    Magic                   IMAGE_NT_OPTIONAL_HDR32_MAGIC")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}       {pe.OPTIONAL_HEADER.MajorLinkerVersion:02X}     Major Linker Version")
    optional_header_offset += 1
    print(f"{optional_header_offset:08X}       {pe.OPTIONAL_HEADER.MinorLinkerVersion:02X}     Minor Linker Version")
    optional_header_offset += 1
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfCode:08X}  Size of Code")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfInitializedData:08X}  Size of Initialized Data")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfUninitializedData:08X}  Size of UnInitialized Data")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.AddressOfEntryPoint:08X}  Address of Entry Point")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.BaseOfCode:08X}  Base of Code")
    optional_header_offset += 4
    if pe.FILE_HEADER.Machine == 0x8664:
        pass
    else:
        print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.BaseOfData:08X}  Base of Data")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.ImageBase:08X} Image Base")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SectionAlignment:08X}  Section Alignment")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.FileAlignment:08X}  File Alignment")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.MajorOperatingSystemVersion:04X}    Major O/S Version")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.MinorOperatingSystemVersion:04X}    Minor O/S Version")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.MajorImageVersion:04X}    Major Image Version")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.MinorImageVersion:04X}    Minor Image Version")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.MajorSubsystemVersion:04X}    Major Subsystem Version")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.MinorSubsystemVersion:04X}    Minor Subsystem Version")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.Reserved1:08X}  Win32 Version Value")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfImage:08X}  Size of Image")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfHeaders:08X}  Size of Headers")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.CheckSum:08X}  Checksum")
    optional_header_offset += 4
    message = print_subsystem_message(pe.OPTIONAL_HEADER.Subsystem)
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.Subsystem:04X}    Subsystem              {message}")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}      {pe.OPTIONAL_HEADER.DllCharacteristics:04X}    DLL Characteristics")
    optional_header_offset += 2
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfStackReserve:08X}  Size of Stack Reserve")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfStackCommit:08X}  Size of Stack Commit")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfHeapReserve:08X}  Size of Heap Reserve")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.SizeOfHeapCommit:08X}  Size of Heap Commit")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.LoaderFlags:08X}  Loader Flags")
    optional_header_offset += 4
    print(f"{optional_header_offset:08X}    {pe.OPTIONAL_HEADER.NumberOfRvaAndSizes:08X}  Number of Data Directories")
    print("-"*70)
    optional_header_offset += 4

    for entry in pe.OPTIONAL_HEADER.DATA_DIRECTORY:
        print(f"{optional_header_offset:08X}    {entry.VirtualAddress:08X}  RVA                    {directory_entry_types.get(entry.name)}")
        optional_header_offset += 4
        print(f"{optional_header_offset:08X}    {entry.Size:08X}  Size")
        optional_header_offset += 4
        print("-"*70)


def print_Section_HEADER(pe, filename):
    print("[IMAGE_SECTION_HEADER]")

    for i in range(1, len(pe.sections)+1):
        print(f"{i}. IMAGE_SECTION_HEADER {pe.sections[i-1].Name.decode('utf-8')}")
    print("")

    select = int(input("출력하고 싶은 섹션 번호 입력> "))

    section_offset = pe.sections[select-1].Name
    with open(filename, 'rb') as f:
        data = f.read()
        section_offset = data.find(section_offset)

    print(f"  pFile   |   Data   |Description            |Value")

    print(f"{section_offset:08X}    {pe.sections[select-1].Name.hex()[0:8]}  Name                    {pe.sections[select-1].Name.decode('utf-8')}")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].Name.hex()[8:16]}")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].Misc:08X}  Virtual Size")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].VirtualAddress:08X}  RVA")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].SizeOfRawData:08X}  Size of Raw Data")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].PointerToRawData:08X}  Pointer to Raw Data")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].PointerToRelocations:08X}  Pointer to Relocations")
    section_offset += 4
    print(f"{section_offset:08X}    {pe.sections[select-1].PointerToLinenumbers:08X}  Pointer to Line Numbers")
    section_offset += 4
    print(f"{section_offset:08X}      {pe.sections[select-1].NumberOfRelocations:04X}    Number of Relocations")
    section_offset += 2
    print(f"{section_offset:08X}      {pe.sections[select-1].NumberOfLinenumbers:04X}    Number of Line Numbers")
    section_offset += 2
    print(f"{section_offset:08X}    {pe.sections[select-1].Characteristics:08X}  Characteristics")
    
    for characteristic, value in section_header_flags:
        if pe.sections[select-1].Characteristics & value:
            print(" " * 22 + f"{value:08X}      {characteristic}")

def print_resource_directory(pe):
    print('[IMAGE_RESOURCE_DIRECTORY Type]')

    for section in pe.sections:
        if section.Name.decode().rstrip('\x00') == ".rsrc":
            offset = section.PointerToRawData

    resource_directory = pe.DIRECTORY_ENTRY_RESOURCE.struct
    print(f'Characteristics: {offset:08X}  {resource_directory.Characteristics:08X}')
    offset += 4
    print(f'TimeDateStamp: {offset:08X}  {resource_directory.TimeDateStamp:08X}  {datetime.fromtimestamp(resource_directory.TimeDateStamp)-timedelta(hours=9)} UTC')
    offset += 4    
    print(f'MajorVersion: {offset:08X}  {resource_directory.MajorVersion:04X}')
    offset += 2    
    print(f'MinorVersion: {offset:08X}  {resource_directory.MinorVersion:04X}')
    offset += 2
    print(f'NumberOfNamedEntries: {offset:08X}  {resource_directory.NumberOfNamedEntries:04X}')
    offset += 2
    print(f'NumberOfIdEntries: {offset:08X}  {resource_directory.NumberOfIdEntries:04X}')


def print_SECTION_list(pe, filename): # 해당 섹션 헥스 값 출력
    for i in range(1, len(pe.sections)+1):
        print(f"{i}. SECTION {pe.sections[i-1].Name.decode('utf-8')}")

    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        print(f"{i+1}. IMAGE_RESOURCE_DIRECTORY_TYPE")

    select = int(input("Enter > "))
    if(select == 6):
        print_resource_directory(pe, )
        return
    offset = pe.sections[select-1].PointerToRawData
    size = pe.sections[select-1].SizeOfRawData

    print(f"  pFile |                     Raw Data                     |Value")
    with open(filename, 'rb') as f:
        data = f.read()
        nt_section = data[offset:offset+size]

        for i in range(0, len(nt_section), 16):
            raw_data = nt_section[i:i+16]
            hex_values = ' '.join([binascii.hexlify(raw_data[i:i+1]).decode('utf-8') for i in range(len(raw_data))])
            ascii_values = ''.join(chr(raw_data[i]) if 31 < raw_data[i] < 127 else '.' for i in range(len(raw_data)))
            print(f'{offset:08X}  {hex_values:<48}  {ascii_values}')
            offset += 16


def main():
    filename = input("    >>> 파일 이름을 입력해 주세요 : 입력> ")

    if(os.path.isfile(filename)):
        print("    >>> 파일을 불러오는데 성공 했습니다.")
        pe = pefile.PE(filename)

        while(1):
            select_menu()
            menu = input("Enter > ")

            if(menu == '1'):
                print_DOS_HEADER(pe, filename)
            elif(menu == '2'):
                print_DOS_Stub(pe)
            elif(menu == '3'):
                print_NT_HEADERS(pe, filename)
            elif(menu == '4'):
                print_NT_Signature(pe)
            elif(menu == '5'):
                print_FILE_HEADER(pe)
            elif(menu == '6'):
                print_OPTIONAL_HEADER(pe)
            elif(menu == '7'):
                print_Section_HEADER(pe, filename)
            else:
                print_SECTION_list(pe, filename)


main()
