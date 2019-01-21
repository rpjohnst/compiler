struct DosHeader {
    uint8_t e_magic[2];
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
    uint32_t e_lfanew;
};

struct CoffHeader {
    uint16_t machine;
    uint16_t number_of_sections;
    uint32_t time_date_stamp;
    uint32_t pointer_to_symbol_table;
    uint32_t number_of_symbols;
    uint16_t size_of_optional_header;
    uint16_t characteristics;
};

enum {
    IMAGE_FILE_MACHINE_UNKNOWN = 0x0,
    IMAGE_FILE_MACHINE_AMD64 = 0x8664,
    IMAGE_FILE_MACHINE_ARM = 0x1c0,
    IMAGE_FILE_MACHINE_ARM64 = 0xaa64,
    IMAGE_FILE_MACHINE_I386 = 0x14c,
};

enum {
    IMAGE_FILE_RELOCS_STRIPPED = 0x0001,
    IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002,
    IMAGE_FILE_LINE_NUMS_STRIPPED = 0x004,
    IMAGE_FILE_LOCAL_SYMS_STRIPPED = 0x008,
    IMAGE_FILE_AGGRESSIVE_WS_TRIM = 0x0010,
    IMAGE_FILE_LARGE_ADDRESS_AWARE = 0x0020,
    IMAGE_FILE_BYTES_REVERSED_LO = 0x0080,
    IMAGE_FILE_32BIT_MACHINE = 0x0100,
    IMAGE_FILE_DEBUG_STRIPPED = 0x0200,
    IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP = 0x0800,
    IMAGE_FILE_SYSTEM = 0x1000,
    IMAGE_FILE_DLL = 0x2000,
    IMAGE_FILE_UP_SYSTEM_ONLY = 0x4000,
    IMAGE_FILE_BYTES_REVERSED_HI = 0x8000,
};

struct Pe32Header {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;
    uint32_t base_of_data;

    uint32_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint32_t size_of_stack_reserve;
    uint32_t size_of_stack_commit;
    uint32_t size_of_heap_reserve;
    uint32_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
};

struct Pe32PlusHeader {
    uint16_t magic;
    uint8_t major_linker_version;
    uint8_t minor_linker_version;
    uint32_t size_of_code;
    uint32_t size_of_initialized_data;
    uint32_t size_of_uninitialized_data;
    uint32_t address_of_entry_point;
    uint32_t base_of_code;

    uint64_t image_base;
    uint32_t section_alignment;
    uint32_t file_alignment;
    uint16_t major_operating_system_version;
    uint16_t minor_operating_system_version;
    uint16_t major_image_version;
    uint16_t minor_image_version;
    uint16_t major_subsystem_version;
    uint16_t minor_subsystem_version;
    uint32_t win32_version_value;
    uint32_t size_of_image;
    uint32_t size_of_headers;
    uint32_t checksum;
    uint16_t subsystem;
    uint16_t dll_characteristics;
    uint64_t size_of_stack_reserve;
    uint64_t size_of_stack_commit;
    uint64_t size_of_heap_reserve;
    uint64_t size_of_heap_commit;
    uint32_t loader_flags;
    uint32_t number_of_rva_and_sizes;
};

enum {
    IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b,
    IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b,
};

enum {
    IMAGE_SUBSYSTEM_UNKNOWN = 0,
    IMAGE_SUBSYSTEM_WINDOWS_GUI = 2,
    IMAGE_SUBSYSTEM_WINDOWS_CUI = 3,
};

enum {
    IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA = 0x0020,
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE = 0x0040,
    IMAGE_DLL_CHARACTERISTICS_FORCE_INTEGRITY = 0x0080,
    IMAGE_DLL_CHARACTERISTICS_NX_COMPAT = 0x0100,
    IMAGE_DLL_CHARACTERISTICS_NO_ISOLATION = 0x0200,
    IMAGE_DLL_CHARACTERISTICS_NO_SEH = 0x0400,
    IMAGE_DLL_CHARACTERISTICS_NO_BIND = 0x0800,
    IMAGE_DLL_CHARACTERISTICS_APPCONTAINER = 0x1000,
    IMAGE_DLL_CHARACTERISTICS_WDM_DRIVER = 0x2000,
    IMAGE_DLL_CHARACTERISTICS_GUARD_CF = 0x4000,
    IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE = 0x8000,
};

struct DataDirectory {
    uint32_t relative_virtual_address;
    uint32_t size;
};

enum {
    IMAGE_DIRECTORY_ENTRY_EXPORT,
    IMAGE_DIRECTORY_ENTRY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_RESOURCE,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION,
    IMAGE_DIRECTORY_ENTRY_SECURITY,
    IMAGE_DIRECTORY_ENTRY_BASERELOC,
    IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_ARCHITECTURE,
    IMAGE_DIRECTORY_ENTRY_GLOBALPTR,
    IMAGE_DIRECTORY_ENTRY_TLS,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
    IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT,
    IMAGE_DIRECTORY_ENTRY_IAT,
    IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT,
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
    IMAGE_DIRECTORY_ENTRY_RESERVED,

    IMAGE_NUMBEROF_DIRECTORY_ENTRIES,
};

enum {
    IMAGE_SIZEOF_SHORT_NAME = 8,
};

struct CoffSection {
    uint8_t name[IMAGE_SIZEOF_SHORT_NAME];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t size_of_raw_data;
    uint32_t pointer_to_raw_data;
    uint32_t pointer_to_relocations;
    uint32_t pointer_to_linenumbers;
    uint16_t number_of_relocations;
    uint16_t number_of_linenumbers;
    uint32_t characteristics;
};

enum {
    IMAGE_SCN_TYPE_NO_PAD = 0x00000008,
    IMAGE_SCN_CNT_CODE = 0x00000020,
    IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040,
    IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080,
    IMAGE_SCN_LNK_OTHER = 0X00000100,
    IMAGE_SCN_LNK_INFO = 0x00000200,
    IMAGE_SCN_LNK_REMOVE = 0x00000800,
    IMAGE_SCN_LNK_COMDAT = 0x00001000,
    IMAGE_SCN_GPREL = 0x00008000,
    IMAGE_SCN_MEM_PURGEABLE = 0x00020000,
    IMAGE_SCN_MEM_LOCKED = 0x00040000,
    IMAGE_SCN_MEM_PRELOAD = 0x00080000,
    IMAGE_SCN_ALIGN_1BYTES = 0x00100000,
    IMAGE_SCN_ALIGN_2BYTES = 0x00200000,
    IMAGE_SCN_ALIGN_4BYTES = 0x00300000,
    IMAGE_SCN_ALIGN_8BYTES = 0x00400000,
    IMAGE_SCN_ALIGN_16BYTES = 0x00500000,
    IMAGE_SCN_ALIGN_32BYTES = 0x00600000,
    IMAGE_SCN_ALIGN_64BYTES = 0x00700000,
    IMAGE_SCN_ALIGN_128BYTES = 0x00800000,
    IMAGE_SCN_ALIGN_256BYTES = 0x00900000,
    IMAGE_SCN_ALIGN_512BYTES = 0x00A00000,
    IMAGE_SCN_ALIGN_1024BYTES = 0x00B00000,
    IMAGE_SCN_ALIGN_2048BYTES = 0x00C00000,
    IMAGE_SCN_ALIGN_4096BYTES = 0x00D00000,
    IMAGE_SCN_ALIGN_8192BYTES = 0x00E00000,
    IMAGE_SCN_LNK_NRELOC_OVFL = 0x01000000,
    IMAGE_SCN_MEM_DISCARDABLE = 0x02000000,
    IMAGE_SCN_MEM_NOT_CACHED = 0x04000000,
    IMAGE_SCN_MEM_NOT_PAGED = 0x08000000,
    IMAGE_SCN_MEM_SHARED = 0x10000000,
    IMAGE_SCN_MEM_EXECUTE = 0x20000000,
    IMAGE_SCN_MEM_READ = 0x40000000,
    IMAGE_SCN_MEM_WRITE = 0x80000000U,
};
