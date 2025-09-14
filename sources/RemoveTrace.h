// RemoveTrace.h
#include <ntifs.h>
#include <ntstrsafe.h>
typedef unsigned char BYTE, *PBYTE;


NTSYSAPI NTSTATUS NTAPI ZwQuerySystemInformation(IN ULONG SystemInformationClass, IN OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength, OUT PULONG ReturnLength);


BOOLEAN DestroyDriverInformation(PDRIVER_OBJECT pDriverObject, WCHAR* DriverName, ULONG64 DriverAddress, BOOLEAN bByName)
{
	ULONG Count = 0;

	PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;

	PLDR_DATA_TABLE_ENTRY firstentry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Blink;

	__try {
		if (!bByName)
		{
			if (DriverAddress >= (ULONG64)firstentry->DllBase && DriverAddress < (ULONG64)firstentry->DllBase + firstentry->SizeOfImage)
			{
				firstentry->BaseDllName.Length = 0;
				firstentry->BaseDllName.MaximumLength = 0;
				firstentry->FullDllName.Length = 0;
				firstentry->FullDllName.MaximumLength = 0;
			}
		}
		else
		{
			if (wcsstr(firstentry->BaseDllName.Buffer, DriverName))
			{
				firstentry->FullDllName.Length = 0;
				firstentry->FullDllName.MaximumLength = 0;
				firstentry->BaseDllName.Length = 0;
				firstentry->BaseDllName.MaximumLength = 0;

				return TRUE;
			}
		}
	}
	__except (1)
	{
	}

	Count++;

	entry = (PLDR_DATA_TABLE_ENTRY)pDriverObject->DriverSection;
	firstentry = entry;
	while ((PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink != firstentry)
	{
		if ((ULONG_PTR)entry->EntryPoint > MmUserProbeAddress)
		{
			__try {
				if (!bByName)
				{
					if (DriverAddress >= (ULONG64)entry->DllBase && DriverAddress < (ULONG64)entry->DllBase + entry->SizeOfImage)
					{
						entry->BaseDllName.Length = 0;
						entry->BaseDllName.MaximumLength = 0;
						return TRUE;
					}
				}
				else
				{
					if (wcsstr(entry->BaseDllName.Buffer, DriverName))
					{
						entry->BaseDllName.Length = 0;
						entry->BaseDllName.MaximumLength = 0;

						return TRUE;
					}
				}
			}
			__except (1)
			{
			}

			Count++;
		}
		entry = (PLDR_DATA_TABLE_ENTRY)entry->InLoadOrderLinks.Flink;
	}

	return FALSE;
}

typedef enum system_information_class_t
{
	SystemBasicInformation = 0,
	SystemProcessorInformation = 1,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemPathInformation = 4,
	SystemProcessInformation = 5,
	SystemCallCountInformation = 6,
	SystemDeviceInformation = 7,
	SystemProcessorPerformanceInformation = 8,
	SystemFlagsInformation = 9,
	SystemCallTimeInformation = 10,
	SystemModuleInformation = 11,
	SystemLocksInformation = 12,
	SystemStackTraceInformation = 13,
	SystemPagedPoolInformation = 14,
	SystemNonPagedPoolInformation = 15,
	SystemHandleInformation = 16,
	SystemObjectInformation = 17,
	SystemPageFileInformation = 18,
	SystemVdmInstemulInformation = 19,
	SystemVdmBopInformation = 20,
	SystemFileCacheInformation = 21,
	SystemPoolTagInformation = 22,
	SystemInterruptInformation = 23,
	SystemDpcBehaviorInformation = 24,
	SystemFullMemoryInformation = 25,
	SystemLoadGdiDriverInformation = 26,
	SystemUnloadGdiDriverInformation = 27,
	SystemTimeAdjustmentInformation = 28,
	SystemSummaryMemoryInformation = 29,
	SystemMirrorMemoryInformation = 30,
	SystemPerformanceTraceInformation = 31,
	SystemObsolete0 = 32,
	SystemExceptionInformation = 33,
	SystemCrashDumpStateInformation = 34,
	SystemKernelDebuggerInformation = 35,
	SystemContextSwitchInformation = 36,
	SystemRegistryQuotaInformation = 37,
	SystemExtendServiceTableInformation = 38,
	SystemPrioritySeperation = 39,
	SystemVerifierAddDriverInformation = 40,
	SystemVerifierRemoveDriverInformation = 41,
	SystemProcessorIdleInformation = 42,
	SystemLegacyDriverInformation = 43,
	SystemCurrentTimeZoneInformation = 44,
	SystemLookasideInformation = 45,
	SystemTimeSlipNotification = 46,
	SystemSessionCreate = 47,
	SystemSessionDetach = 48,
	SystemSessionInformation = 49,
	SystemRangeStartInformation = 50,
	SystemVerifierInformation = 51,
	SystemVerifierThunkExtend = 52,
	SystemSessionProcessInformation = 53,
	SystemLoadGdiDriverInSystemSpace = 54,
	SystemNumaProcessorMap = 55,
	SystemPrefetcherInformation = 56,
	SystemExtendedProcessInformation = 57,
	SystemRecommendedSharedDataAlignment = 58,
	SystemComPlusPackage = 59,
	SystemNumaAvailableMemory = 60,
	SystemProcessorPowerInformation = 61,
	SystemEmulationBasicInformation = 62,
	SystemEmulationProcessorInformation = 63,
	SystemExtendedHandleInformation = 64,
	SystemLostDelayedWriteInformation = 65,
	SystemBigPoolInformation = 66,
	SystemSessionPoolTagInformation = 67,
	SystemSessionMappedViewInformation = 68,
	SystemHotpatchInformation = 69,
	SystemObjectSecurityMode = 70,
	SystemWatchdogTimerHandler = 71,
	SystemWatchdogTimerInformation = 72,
	SystemLogicalProcessorInformation = 73,
	SystemWow64SharedInformation = 74,
	SystemRegisterFirmwareTableInformationHandler = 75,
	SystemFirmwareTableInformation = 76,
	SystemModuleInformationEx = 77,
	SystemVerifierTriageInformation = 78,
	SystemSuperfetchInformation = 79,
	SystemMemoryListInformation = 80,
	SystemFileCacheInformationEx = 81,
	MaxSystemInfoClass = 82  // MaxSystemInfoClass should always be the last enum

}system_information_class;

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

BOOLEAN bDataCompare(const BYTE* pData, const BYTE* bMask, const char* szMask)
{
	for (; *szMask; ++szMask, ++pData, ++bMask)
		if (*szMask == 'x' && *pData != *bMask)
			return 0;

	return (*szMask) == 0;
}

UINT64 FindPattern(UINT64 dwAddress, UINT64 dwLen, BYTE *bMask, char * szMask)
{
	for (UINT64 i = 0; i < dwLen; i++)
		if (bDataCompare((BYTE*)(dwAddress + i), bMask, szMask))
			return (UINT64)(dwAddress + i);

	return 0;
}

BOOLEAN CleanUnloadedDrivers()
{
	ULONG bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, 0, bytes, &bytes);

	if (!bytes)
	{
		//DEBUGPRINT("CleanUnloadedDrivers: first NtQuerySystemInformation failed, status: 0x%x", status);
		return FALSE;
	}

	PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 0x37126DD); // 'ENON'

	status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);

	if (!NT_SUCCESS(status))
	{
		//DEBUGPRINT("CleanUnloadedDrivers: second NtQuerySystemInformation failed, status: 0x%x", status);
		return FALSE;
	}

	PRTL_PROCESS_MODULE_INFORMATION module = modules->Modules;
	UINT64 ntoskrnlBase = 0, ntoskrnlSize = 0;

	for (ULONG i = 0; i < modules->NumberOfModules; i++)
	{
		//DEBUGPRINT("CleanUnloadedDrivers: path: %s", module[i].FullPathName);

		if (!strcmp((char*)module[i].FullPathName, "\\SystemRoot\\system32\\ntoskrnl.exe"))
		{
			ntoskrnlBase = (UINT64)module[i].ImageBase;
			ntoskrnlSize = (UINT64)module[i].ImageSize;
			break;
		}
	}

	if (modules)
		ExFreePoolWithTag(modules, 0);

	if (ntoskrnlBase <= 0)
	{
		//DEBUGPRINT("CleanUnloadedDrivers: ntoskrnlBase equals zero");
		return FALSE;
	}

	// NOTE: 4C 8B ? ? ? ? ? 4C 8B C9 4D 85 ? 74 + 3] + current signature address = MmUnloadedDrivers
	UINT64 mmUnloadedDriversPtr = FindPattern((UINT64)ntoskrnlBase, (UINT64)ntoskrnlSize, (BYTE*)"\x4C\x8B\x00\x00\x00\x00\x00\x4C\x8B\xC9\x4D\x85\x00\x74", "xx?????xxxxx?x");

	if (!mmUnloadedDriversPtr)
	{
		//DEBUGPRINT("CleanUnloadedDrivers: mmUnloadedDriversPtr equals zero");
		return FALSE;
	}

	UINT64 mmUnloadedDrivers = (UINT64)((PUCHAR)mmUnloadedDriversPtr + *(PULONG)((PUCHAR)mmUnloadedDriversPtr + 3) + 7);
	UINT64 bufferPtr = *(UINT64*)mmUnloadedDrivers;

	// NOTE: 0x7D0 is the size of the MmUnloadedDrivers array for win 7 and above
	PVOID newBuffer = ExAllocatePoolWithTag(NonPagedPoolNx, 0x7D0, 0x51313DD);

	if (!newBuffer)
		return FALSE;

	memset(newBuffer, 0, 0x7D0);

	// NOTE: replace MmUnloadedDrivers
	*(UINT64*)mmUnloadedDrivers = (UINT64)newBuffer;

	// NOTE: clean the old buffer
	ExFreePoolWithTag((PVOID)bufferPtr, 0x51313DD); // 'MmDT'

	return TRUE;
}


#define MM_UNLOADED_DRIVERS_SIZE 50
typedef struct _MM_UNLOADED_DRIVER
{
	UNICODE_STRING 	Name;
	PVOID 			ModuleStart;
	PVOID 			ModuleEnd;
	ULONG64 		UnloadTime;
} MM_UNLOADED_DRIVER, *PMM_UNLOADED_DRIVER;

PMM_UNLOADED_DRIVER MmUnloadedDrivers;
PULONG				MmLastUnloadedDriver;

PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

BOOLEAN IsUnloadedDriverEntryEmpty(
	_In_ PMM_UNLOADED_DRIVER Entry
)
{
	if (Entry->Name.MaximumLength == 0 ||
		Entry->Name.Length == 0 ||
		Entry->Name.Buffer == NULL)
	{
		return TRUE;
	}

	return FALSE;
}

BOOLEAN IsMmUnloadedDriversFilled(
	VOID
)
{
	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (IsUnloadedDriverEntryEmpty(Entry))
		{
			return FALSE;
		}
	}

	return TRUE;
}

extern NTKERNELAPI ERESOURCE PsLoadedModuleResource;
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;
typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void);
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;

NTSTATUS ClearUnloadedDriver(
	_In_ PUNICODE_STRING	DriverName,
	_In_ BOOLEAN			AccquireResource
)
{
	if (AccquireResource)
	{
		ExAcquireResourceExclusiveLite(&PsLoadedModuleResource, TRUE);
	}

	BOOLEAN Modified = FALSE;
	BOOLEAN Filled = IsMmUnloadedDriversFilled();

	for (ULONG Index = 0; Index < MM_UNLOADED_DRIVERS_SIZE; ++Index)
	{
		PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
		if (Modified)
		{
			//
			// Shift back all entries after modified one.
			//
			PMM_UNLOADED_DRIVER PrevEntry = &MmUnloadedDrivers[Index - 1];
			RtlCopyMemory(PrevEntry, Entry, sizeof(MM_UNLOADED_DRIVER));

			//
			// Zero last entry.
			//
			if (Index == MM_UNLOADED_DRIVERS_SIZE - 1)
			{
				RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			}
		}
		else if (RtlEqualUnicodeString(DriverName, &Entry->Name, TRUE))
		{
			//
			// Erase driver entry.
			//
			PVOID BufferPool = Entry->Name.Buffer;
			RtlFillMemory(Entry, sizeof(MM_UNLOADED_DRIVER), 0);
			ExFreePoolWithTag(BufferPool, 0x51313DD); // 0x54446D4D

			//
			// Because we are erasing last entry we want to set MmLastUnloadedDriver to 49
			// if list have been already filled.
			//
			*MmLastUnloadedDriver = (Filled ? MM_UNLOADED_DRIVERS_SIZE : *MmLastUnloadedDriver) - 1;
			Modified = TRUE;
		}
	}

	if (Modified)
	{
		ULONG64 PreviousTime = 0;

		//
		// Make UnloadTime look right.
		//
		for (LONG Index = MM_UNLOADED_DRIVERS_SIZE - 2; Index >= 0; --Index)
		{
			PMM_UNLOADED_DRIVER Entry = &MmUnloadedDrivers[Index];
			if (IsUnloadedDriverEntryEmpty(Entry))
			{
				continue;
			}

			if (PreviousTime != 0 && Entry->UnloadTime > PreviousTime)
			{
				//
				// Decrease by random value here maybe.
				//
				Entry->UnloadTime = PreviousTime - 100;
			}

			PreviousTime = Entry->UnloadTime;
		}

		//
		// Clear remaining entries.
		//
		ClearUnloadedDriver(DriverName, FALSE);
	}

	if (AccquireResource)
	{
		ExReleaseResourceLite(&PsLoadedModuleResource);
	}

	return Modified ? STATUS_SUCCESS : STATUS_NOT_FOUND;
}