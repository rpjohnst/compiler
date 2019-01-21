#include <string.h>
#include <stdint.h>

inline static uint64_t divide_ceil(uint64_t numerator, uint64_t denominator) {
    return (numerator + denominator - 1) / denominator;
}

inline static uint64_t align_to(uint64_t value, uint64_t align) {
    return divide_ceil(value, align) * align;
}

#include "pe.h"
#include "pe.c"

static const uint8_t program[] = {
    0x31, 0xc0, // xor eax, eax
    0xc3,       // ret
};

#include <windef.h>
#include <WinBase.h>
#include <fileapi.h>

int __stdcall mainCRTStartup(void) {
    HANDLE file = CreateFileW(L"output.tmp", GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return 1;
    }

    HANDLE mapping = CreateFileMappingW(file, NULL, PAGE_READWRITE, 0, 0x1000, NULL);
    if (mapping == NULL) {
        return 1;
    }

    void *view = MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 0x1000);
    if (view == NULL) {
        return 1;
    }
    CloseHandle(mapping);

    write_image(view, &program, sizeof(program));

    UnmapViewOfFile(view);
    FlushFileBuffers(file);
    CloseHandle(file);

    if (MoveFileExW(L"output.tmp", L"output.exe", MOVEFILE_REPLACE_EXISTING) == 0) {
        return 1;
    }

    return 0;
}

#if __clang__
void *memcpy(void *restrict dst, const void *restrict src, size_t count)
#elif _MSC_VER
#pragma function(memcpy)
void *memcpy(void *dst, const void *src, size_t count)
#else
#error Unknown compiler
#endif
{
    char *d = dst;
    const char *s = src;
    while (count--) {
        *d++ = *s++;
    }
    return dst;
}
