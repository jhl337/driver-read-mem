// struct.h
#pragma once

#if defined(_AMD64_)
int kVarBit = 0x28;  // DirectoryTableBase offset for x64
#else
int kVarBit = 0x18;  // DirectoryTableBase offset for x86
#endif

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
} PEB32, * PPEB32;
typedef struct _PEB64 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	UCHAR Padding0[4];
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64 Ldr;
} PEB64, * PPEB64;
typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONG LoadedImports;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
	ULONG ContextInformation;
	ULONG OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;
typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;
typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;
typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	LIST_ENTRY InInitializationOrderLinks;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	short LoadCount;
	short TlsIndex;
	union
	{
		LIST_ENTRY HashLinks;
		struct
		{
			PVOID SectionPointer;
			ULONG CheckSum;
		};
	};
	union
	{
		ULONG TimeDateStamp;
		PVOID LoadedImports;
	};
	PVOID* EntryPointActivationContext;
	PVOID PatchInformation;
	LIST_ENTRY ForwarderLinks;
	LIST_ENTRY ServiceTagLinks;
	LIST_ENTRY StaticLinks;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef PPEB32(*PPS_GET_PROCESS_WOW64_PROCESS)(IN PEPROCESS Process);
typedef PPEB64(*PPS_GET_PROCESS_PEB)(IN PEPROCESS Process);
typedef PVOID (*PMM_GET_VIRTUAL_FOR_PHYSICAL)(IN PHYSICAL_ADDRESS PhysicalAddress);
typedef NTSTATUS(*PPS_LOOKUP_PROCESS_BY_PROCESS_ID)(
	HANDLE ProcessId,
	PEPROCESS* Process
	);

typedef NTSTATUS(*PMM_COPY_MEMORY)(
	_Out_ PVOID           TargetAddress,
	_In_  MM_COPY_ADDRESS SourceAddress,
	_In_  SIZE_T          NumberOfBytes,
	_In_  ULONG           Flags,
	_Out_ PSIZE_T         NumberOfBytesTransferred
	);

typedef NTSTATUS(*PRTL_CREATE_REGISTRY_KEY)(
	IN ULONG RelativeTo,
	IN PWSTR Path
	);

typedef NTSTATUS(*PRTL_WRITE_REGISTRY_VALUE)(
	IN ULONG RelativeTo,
	IN PCWSTR Path,
	IN PCWSTR ValueName,
	IN ULONG ValueType,
	IN PVOID ValueData,
	IN ULONG ValueLength
	);

#pragma pack(push, 1)
typedef union CR3_
{
    ULONG64 Value;
    struct
    {
        ULONG64 Ignored1 : 3;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Ignored2 : 7;
        ULONG64 Pml4 : 40;
        ULONG64 Reserved : 12;
    };
} PTE_CR3;

typedef union VIRT_ADDR_
{
    ULONG64 Value;
    void* Pointer;
    struct
    {
        ULONG64 Offset : 12;
        ULONG64 PtIndex : 9;
        ULONG64 PdIndex : 9;
        ULONG64 PdptIndex : 9;
        ULONG64 Pml4Index : 9;
        ULONG64 Reserved : 16;
    };
} VIRTUAL_ADDRESS;

typedef union PML4E_
{
    ULONG64 Value;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Rw : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Ignored1 : 1;
        ULONG64 Reserved1 : 1;
        ULONG64 Ignored2 : 4;
        ULONG64 Pdpt : 40;
        ULONG64 Ignored3 : 11;
        ULONG64 Xd : 1;
    };
} PML4E;

typedef union PDPTE_
{
    ULONG64 Value;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Rw : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 PageSize : 1;
        ULONG64 Ignored2 : 4;
        ULONG64 Pd : 40;
        ULONG64 Ignored3 : 11;
        ULONG64 Xd : 1;
    };
} PDPTE;

typedef union PDE_
{
    ULONG64 Value;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Rw : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 PageSize : 1;
        ULONG64 Ignored2 : 4;
        ULONG64 Pt : 40;
        ULONG64 Ignored3 : 11;
        ULONG64 Xd : 1;
    };
} PDE;
typedef union PTE_
{
    ULONG64 Value;
    VIRTUAL_ADDRESS VirtualAddress;
    struct
    {
        ULONG64 Present : 1;
        ULONG64 Rw : 1;
        ULONG64 User : 1;
        ULONG64 WriteThrough : 1;
        ULONG64 CacheDisable : 1;
        ULONG64 Accessed : 1;
        ULONG64 Dirty : 1;
        ULONG64 Pat : 1;
        ULONG64 Global : 1;
        ULONG64 Ignored1 : 3;
        ULONG64 PFN : 40;
        ULONG64 Ignored3 : 11;
        ULONG64 Xd : 1;
    };
} PTE;
typedef struct _MMPTE_HARDWARE
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 Dirty1 : 1; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 Owner : 1; /* bit position: 2 */
        /* 0x0000 */ unsigned __int64 WriteThrough : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned __int64 CacheDisable : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Accessed : 1; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Dirty : 1; /* bit position: 6 */
        /* 0x0000 */ unsigned __int64 LargePage : 1; /* bit position: 7 */
        /* 0x0000 */ unsigned __int64 Global : 1; /* bit position: 8 */
        /* 0x0000 */ unsigned __int64 CopyOnWrite : 1; /* bit position: 9 */
        /* 0x0000 */ unsigned __int64 Unused : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
        /* 0x0000 */ unsigned __int64 ReservedForHardware : 4; /* bit position: 48 */
        /* 0x0000 */ unsigned __int64 ReservedForSoftware : 4; /* bit position: 52 */
        /* 0x0000 */ unsigned __int64 WsleAge : 4; /* bit position: 56 */
        /* 0x0000 */ unsigned __int64 WsleProtection : 3; /* bit position: 60 */
        /* 0x0000 */ unsigned __int64 NoExecute : 1; /* bit position: 63 */
    }; /* bitfield */
} MMPTE_HARDWARE, * PMMPTE_HARDWARE; /* size: 0x0008 */

typedef struct _MMPTE_PROTOTYPE
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 DemandFillProto : 1; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 HiberVerifyConverted : 1; /* bit position: 2 */
        /* 0x0000 */ unsigned __int64 ReadOnly : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 Combined : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 Unused1 : 4; /* bit position: 12 */
        /* 0x0000 */ __int64 ProtoAddress : 48; /* bit position: 16 */
    }; /* bitfield */
} MMPTE_PROTOTYPE, * PMMPTE_PROTOTYPE; /* size: 0x0008 */

typedef struct _MMPTE_SOFTWARE
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 PageFileReserved : 1; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 PageFileAllocated : 1; /* bit position: 2 */
        /* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
        /* 0x0000 */ unsigned __int64 UsedPageTableEntries : 10; /* bit position: 16 */
        /* 0x0000 */ unsigned __int64 ShadowStack : 1; /* bit position: 26 */
        /* 0x0000 */ unsigned __int64 Unused : 5; /* bit position: 27 */
        /* 0x0000 */ unsigned __int64 PageFileHigh : 32; /* bit position: 32 */
    }; /* bitfield */
} MMPTE_SOFTWARE, * PMMPTE_SOFTWARE; /* size: 0x0008 */

typedef struct _MMPTE_TIMESTAMP
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 MustBeZero : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 Unused : 3; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 PageFileLow : 4; /* bit position: 12 */
        /* 0x0000 */ unsigned __int64 Reserved : 16; /* bit position: 16 */
        /* 0x0000 */ unsigned __int64 GlobalTimeStamp : 32; /* bit position: 32 */
    }; /* bitfield */
} MMPTE_TIMESTAMP, * PMMPTE_TIMESTAMP; /* size: 0x0008 */

typedef struct _MMPTE_TRANSITION
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 Write : 1; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 Spare : 1; /* bit position: 2 */
        /* 0x0000 */ unsigned __int64 IoTracker : 1; /* bit position: 3 */
        /* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 PageFrameNumber : 36; /* bit position: 12 */
        /* 0x0000 */ unsigned __int64 Unused : 16; /* bit position: 48 */
    }; /* bitfield */
} MMPTE_TRANSITION, * PMMPTE_TRANSITION; /* size: 0x0008 */

typedef struct _MMPTE_SUBSECTION
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 Unused0 : 3; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 ColdPage : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 Unused1 : 3; /* bit position: 12 */
        /* 0x0000 */ unsigned __int64 ExecutePrivilege : 1; /* bit position: 15 */
        /* 0x0000 */ __int64 SubsectionAddress : 48; /* bit position: 16 */
    }; /* bitfield */
} MMPTE_SUBSECTION, * PMMPTE_SUBSECTION; /* size: 0x0008 */

typedef struct _MMPTE_LIST
{
    struct /* bitfield */
    {
        /* 0x0000 */ unsigned __int64 Valid : 1; /* bit position: 0 */
        /* 0x0000 */ unsigned __int64 OneEntry : 1; /* bit position: 1 */
        /* 0x0000 */ unsigned __int64 filler0 : 2; /* bit position: 2 */
        /* 0x0000 */ unsigned __int64 SwizzleBit : 1; /* bit position: 4 */
        /* 0x0000 */ unsigned __int64 Protection : 5; /* bit position: 5 */
        /* 0x0000 */ unsigned __int64 Prototype : 1; /* bit position: 10 */
        /* 0x0000 */ unsigned __int64 Transition : 1; /* bit position: 11 */
        /* 0x0000 */ unsigned __int64 filler1 : 16; /* bit position: 12 */
        /* 0x0000 */ unsigned __int64 NextEntry : 36; /* bit position: 28 */
    }; /* bitfield */
} MMPTE_LIST, * PMMPTE_LIST; /* size: 0x0008 */

typedef struct _MMPTE
{
    union
    {
        union
        {
            /* 0x0000 */ unsigned __int64 Long;
            /* 0x0000 */ volatile unsigned __int64 VolatileLong;
            /* 0x0000 */ struct _MMPTE_HARDWARE Hard;
            /* 0x0000 */ struct _MMPTE_PROTOTYPE Proto;
            /* 0x0000 */ struct _MMPTE_SOFTWARE Soft;
            /* 0x0000 */ struct _MMPTE_TIMESTAMP TimeStamp;
            /* 0x0000 */ struct _MMPTE_TRANSITION Trans;
            /* 0x0000 */ struct _MMPTE_SUBSECTION Subsect;
            /* 0x0000 */ struct _MMPTE_LIST List;
        }; /* size: 0x0008 */
    } /* size: 0x0008 */ u;
} MMPTE, * PMMPTE; /* size: 0x0008 */
#pragma pack(pop)

