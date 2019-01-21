static const uint8_t PE_MAGIC[] = { 'P', 'E', 0, 0 };

static const uint8_t dos_program[] = {
    // Address data relative to this program.
    0x0e,             // push cs
    0x1f,             // pop ds

    // Print string.
    0xba, 0x0e, 0x00, // mov dx, 000eh
    0xb4, 0x09,       // mov ah, 09h
    0xcd, 0x21,       // int 21h

    // Exit.
    0xb8, 0x01, 0x4c, // mov ax, 4c01h
    0xcd, 0x21,       // int 21h

    'T', 'h', 'i', 's', ' ', 'p', 'r', 'o', 'g', 'r', 'a', 'm', ' ', 'c', 'a', 'n', 'n', 'o', 't',
    ' ', 'b', 'e', ' ', 'r', 'u', 'n', ' ', 'i', 'n', ' ', 'D', 'O', 'S', ' ', 'm', 'o', 'd', 'e',
    '.', '$', 0x00, 0x00,
};

enum {
    DOS_STUB_SIZE = sizeof(struct DosHeader) + sizeof(dos_program),
};

void write_image(void *view, const void *text, size_t text_len) {
    char *buffer = view;

    // Write DOS header. PE/COFF executables begin with a stub DOS executable.
    struct DosHeader *dos = (void*)buffer;
    buffer += sizeof(*dos);
    dos->e_magic[0] = 'M';
    dos->e_magic[1] = 'Z';
    dos->e_cblp = DOS_STUB_SIZE % 0x200;
    dos->e_cp = (uint16_t)divide_ceil(DOS_STUB_SIZE, 0x200);
    dos->e_cparhdr = sizeof(struct DosHeader) / 16;
    dos->e_lfarlc = sizeof(struct DosHeader);
    dos->e_lfanew = DOS_STUB_SIZE;

    // Write DOS program.
    memcpy(buffer, &dos_program, sizeof(dos_program));
    buffer += sizeof(dos_program);

    // Write PE magic.
    memcpy(buffer, &PE_MAGIC, sizeof(PE_MAGIC));
    buffer += sizeof(PE_MAGIC);

    // Write COFF header.
    struct CoffHeader *coff = (void*)buffer;
    buffer += sizeof(*coff);
    coff->machine = IMAGE_FILE_MACHINE_AMD64;
    coff->number_of_sections = 1;
    coff->size_of_optional_header = sizeof(struct Pe32PlusHeader) + IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(struct DataDirectory);
    coff->characteristics = IMAGE_FILE_RELOCS_STRIPPED | IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE;

    // Write PE32+ header.
    struct Pe32PlusHeader *pe = (void*)buffer;
    buffer += sizeof(*pe);
    pe->magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    pe->major_linker_version = 0;
    pe->minor_linker_version = 0;
    pe->size_of_code = (uint32_t)align_to(text_len, 0x200);
    pe->size_of_initialized_data = 0;
    pe->size_of_uninitialized_data = 0;
    pe->address_of_entry_point = 0x1000;
    pe->base_of_code = 0x1000;
    pe->image_base = 0x140000000;
    pe->section_alignment = 0x1000;
    pe->file_alignment = 0x200;
    pe->major_operating_system_version = 6;
    pe->minor_operating_system_version = 0;
    pe->major_image_version = 0;
    pe->minor_image_version = 0;
    pe->major_subsystem_version = 6;
    pe->minor_subsystem_version = 0;
    pe->win32_version_value = 0;
    pe->size_of_image = 0x2000;
    pe->size_of_headers = 0x200;
    pe->checksum = 0;
    pe->subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    pe->dll_characteristics = IMAGE_DLL_CHARACTERISTICS_HIGH_ENTROPY_VA | IMAGE_DLL_CHARACTERISTICS_NX_COMPAT | IMAGE_DLL_CHARACTERISTICS_TERMINAL_SERVER_AWARE;
    pe->size_of_stack_reserve = 0x100000;
    pe->size_of_stack_commit = 0x1000;
    pe->size_of_heap_reserve = 0x100000;
    pe->size_of_heap_commit = 0x1000;
    pe->loader_flags = 0;
    pe->number_of_rva_and_sizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    struct DataDirectory *dir = (void*)buffer;
    buffer += pe->number_of_rva_and_sizes * sizeof(*dir);

    // Write .text section.
    struct CoffSection *section = (void*)buffer;
    buffer += sizeof(*section);
    memcpy(section->name, ".text", 5);
    section->virtual_size = (uint32_t)text_len;
    section->virtual_address = 0x1000;
    section->size_of_raw_data = (uint32_t)align_to(text_len, 0x200);
    section->pointer_to_raw_data = (uint32_t)align_to((uintptr_t)(buffer - (char*)view), 0x200);
    section->characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    // Write .text.
    buffer = (void*)align_to((uintptr_t)buffer, 0x200);
    memcpy(buffer, text, text_len);
    buffer += text_len;
}
