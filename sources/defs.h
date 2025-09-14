// defs.h
#pragma once

// Command flags
#define READ 0xACE
#define GETMODULE 0xCEF
#define XOR_KEY 0x28

// Page conversion macros
#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)
#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

typedef unsigned __int64 ULONGLONG;

// Driver communication structure
typedef struct _Driver {
	ULONG flag;         // Operation type (READ/GETMODULE)
	ULONG pid;          // Target process ID
	ULONG64 address;    // Memory address to read
	ULONG64 buffer;     // Output buffer address
	ULONG size;         // Size of data to read
} Driver, * PDriver;

// Page mapping structure
typedef struct _PAGE {
	PVOID VirtualAddress;   // Virtual address of mapped page
	PTE* PTE;               // Corresponding PTE
	ULONG64 PreviousPageFrame;  // Original PFN
} _PAGE;

// CPU context structure
typedef struct _MY_ATTACH_OBJ {
	ULONG64 cr0;
	ULONG64 cr3;
	ULONG64 cr4;
} MY_ATTACH_OBJ, * PMY_ATTACH_OBJ;

// Global function pointers
LARGE_INTEGER Cookie = { 0 };
PPS_LOOKUP_PROCESS_BY_PROCESS_ID PsLookupProcessByProcessIdPtr = NULL;
PPS_GET_PROCESS_WOW64_PROCESS PsGetProcessWow64ProcessPtr = NULL;
PPS_GET_PROCESS_PEB PsGetProcessPebPtr = NULL;
PMM_GET_VIRTUAL_FOR_PHYSICAL MmGetVirtualForPhysicalPtr = NULL;