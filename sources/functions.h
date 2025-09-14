// functions.h
#pragma once

// Internal Functions
#if !defined(CR4_PGE)
#define CR4_PGE (1UL << 7)
#endif

#if !defined(CR4_PCIDE)
#define CR4_PCIDE (1UL << 17)
#endif

RTL_OSVERSIONINFOW Version;

// Get DirectoryTableBase offset based on Windows build number
ULONG GetDirectoryTableOffset() {
    RtlGetVersion(&Version);
    switch (Version.dwBuildNumber) {
    case 17763: // 1809
        return 0x0278;
    case 18363: // 1909
        return 0x0280;
    case 19041: // 2004
    case 19569: // 20H2
    case 20180: // 21H1
        return 0x0388;
    default:
        return 0x0388; // Default for newer versions
    }
}

// Safely switch CR3 register
__forceinline void SafeCr3Switch(ULONG64 NewCr3) {
    _mm_mfence();
    // const ULONG64 cr4 = __readcr4();
    //__writecr4(cr4 & ~(CR4_PGE | CR4_PCIDE));
    __writecr3(NewCr3);
    __invlpg(0);
    // __writecr4(cr4);
    _mm_lfence();
}

// Get process CR3 value
ULONG64 GetProcessCr3(PEPROCESS Process) {
    ULONG64 CR3 = *(ULONG64*)((PUCHAR)Process + kVarBit);
    if (!CR3) CR3 = *(ULONG64*)((PUCHAR)Process + GetDirectoryTableOffset());
    return CR3;
}

// Securely zero memory with memory barriers
void StealthZeroMemory(volatile void* dest, size_t size) {
    volatile UCHAR* p = (volatile UCHAR*)dest;
    while (size--) {
        *p++ = 0;
        _mm_lfence();
    }
    _mm_sfence();
}