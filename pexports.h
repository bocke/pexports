/*
 pexports - a program to extract exported symbols from a Portable
 Executable (PE) file.

 Copyright (C) 1998 Anders Norlander

 pexports is distributed under the GNU General Public License and
 has absolutely NO WARRANTY.

 pexports will work only on intel machines.
*/
#ifndef _pexports_h
#define _pexports_h

#include <stdio.h>
#include <stdint.h>

#include "str_tree.h"

#define FALSE (int32_t)(0)
#define TRUE  (int32_t)(1)

/* PE structures */
typedef struct IMAGE_DATA_DIRECTORY {
  uint32_t   VirtualAddress;
  uint32_t   Size;
} IMAGE_DATA_DIRECTORY;

typedef struct IMAGE_FILE_HEADER {
  uint16_t   Machine;
  uint16_t   NumberOfSections;
  uint32_t   TimeDateStamp;
  uint32_t   PointerToSymbolTable;
  uint32_t   NumberOfSymbols;
  uint16_t   SizeOfOptionalHeader;
  uint16_t   Characteristics;
} IMAGE_FILE_HEADER;

#define IMAGE_FILE_MACHINE_I386  0x014c
#define IMAGE_FILE_MACHINE_IA64  0x0200
#define IMAGE_FILE_MACHINE_AMD64 0x8664

typedef struct IMAGE_OPTIONAL_HEADER32 {
  uint16_t   Magic;
  uint8_t    MajorLinkerVersion;
  uint8_t    MinorLinkerVersion;
  uint32_t   SizeOfCode;
  uint32_t   SizeOfInitializedData;
  uint32_t   SizeOfUninitializedData;
  uint32_t   AddressOfEntryPoint;
  uint32_t   BaseOfCode;
  uint32_t   BaseOfData;
  uint32_t   ImageBase;
  uint32_t   SectionAlignment;
  uint32_t   FileAlignment;
  uint16_t   MajorOperatingSystemVersion;
  uint16_t   MinorOperatingSystemVersion;
  uint16_t   MajorImageVersion;
  uint16_t   MinorImageVersion;
  uint16_t   MajorSubsystemVersion;
  uint16_t   MinorSubsystemVersion;
  uint32_t   Reserved1;
  uint32_t   SizeOfImage;
  uint32_t   SizeOfHeaders;
  uint32_t   CheckSum;
  uint16_t   Subsystem;
  uint16_t   DllCharacteristics;
  uint32_t   SizeOfStackReserve;
  uint32_t   SizeOfStackCommit;
  uint32_t   SizeOfHeapReserve;
  uint32_t   SizeOfHeapCommit;
  uint32_t   LoaderFlags;
  uint32_t   NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER32;

typedef struct IMAGE_OPTIONAL_HEADER64 {
  uint16_t   Magic;
  uint8_t    MajorLinkerVersion;
  uint8_t    MinorLinkerVersion;
  uint32_t   SizeOfCode;
  uint32_t   SizeOfInitializedData;
  uint32_t   SizeOfUninitializedData;
  uint32_t   AddressOfEntryPoint;
  uint32_t   BaseOfCode;
  uint64_t   ImageBase;
  uint32_t   SectionAlignment;
  uint32_t   FileAlignment;
  uint16_t   MajorOperatingSystemVersion;
  uint16_t   MinorOperatingSystemVersion;
  uint16_t   MajorImageVersion;
  uint16_t   MinorImageVersion;
  uint16_t   MajorSubsystemVersion;
  uint16_t   MinorSubsystemVersion;
  uint32_t   Win32VersionValue;
  uint32_t   SizeOfImage;
  uint32_t   SizeOfHeaders;
  uint32_t   CheckSum;
  uint16_t   Subsystem;
  uint16_t   DllCharacteristics;
  uint64_t   SizeOfStackReserve;
  uint64_t   SizeOfStackCommit;
  uint64_t   SizeOfHeapReserve;
  uint64_t   SizeOfHeapCommit;
  uint32_t   LoaderFlags;
  uint32_t   NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[16];
} IMAGE_OPTIONAL_HEADER64;

typedef struct IMAGE_NT_HEADERS32 {
  char Signature[4];
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32;

typedef struct IMAGE_NT_HEADERS64 {
  char Signature[4];
  IMAGE_FILE_HEADER FileHeader;
  IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64;

typedef struct IMAGE_SECTION_HEADER {
  uint8_t    Name[8];
  union {
    uint32_t PhysicalAddress;
    uint32_t VirtualSize;
  } Misc;
  uint32_t   VirtualAddress;
  uint32_t   SizeOfRawData;
  uint32_t   PointerToRawData;
  uint32_t   PointerToRelocations;
  uint32_t   PointerToLinenumbers;
  uint16_t   NumberOfRelocations;
  uint16_t   NumberOfLinenumbers;
  uint32_t   Characteristics;
} IMAGE_SECTION_HEADER;

#define IMAGE_SCN_CNT_CODE 0x00000020

typedef struct IMAGE_EXPORT_DIRECTORY {
  uint32_t   Characteristics;
  uint32_t   TimeDateStamp;
  uint16_t   MajorVersion;
  uint16_t   MinorVersion;
  uint32_t   Name;
  uint32_t   Base;
  uint32_t   NumberOfFunctions;
  uint32_t   NumberOfNames;
  uint32_t   AddressOfFunctions;
  uint32_t   AddressOfNames;
  uint32_t   AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct IMAGE_DOS_HEADER {
  uint16_t   e_magic;
  uint16_t   e_cblp;
  uint16_t   e_cp;
  uint16_t   e_crlc;
  uint16_t   e_cparhdr;
  uint16_t   e_minalloc;
  uint16_t   e_maxalloc;
  uint16_t   e_ss;
  uint16_t   e_sp;
  uint16_t   e_csum;
  uint16_t   e_ip;
  uint16_t   e_cs;
  uint16_t   e_lfarlc;
  uint16_t   e_ovno;
  uint16_t   e_res[4];
  uint16_t   e_oemid;
  uint16_t   e_oeminfo;
  uint16_t   e_res2[10];
  int32_t    e_lfanew;
} IMAGE_DOS_HEADER;

IMAGE_SECTION_HEADER *find_section( uint32_t );
IMAGE_DOS_HEADER *load_pe_image( const char * );

void *rva_to_ptr( uint32_t );
void dump_exports( uint32_t, uint32_t );

#define ADD_FUNCTION(nm,n) str_tree_add(&symbols, nm, (void*)(intptr_t)(n))
extern str_tree *symbols;

#endif /* _pexports_h */
