// Cr3.cpp
#include "imports.h"
#include "struct.h"
#include "defs.h"
#include "functions.h"

namespace ReadPageMemory {
    // Global page mapping array
    _PAGE PageList[64];

    // Convert physical address to virtual address
    PVOID PhysicalToVirtual(ULONG64 address) {
        PHYSICAL_ADDRESS physical;
        physical.QuadPart = address;
        return MmGetVirtualForPhysicalPtr(physical);
    }

    // Get PTE for a virtual address
    PTE* MemoryGetPte(const ULONG64 address) {
        VIRTUAL_ADDRESS virtualAddress;
        virtualAddress.Value = address;
        PTE_CR3 cr3;
        cr3.Value = __readcr3();

        // Walk page tables
        PML4E* pml4 = (PML4E*)(PhysicalToVirtual(PFN_TO_PAGE(cr3.Pml4)));
        const PML4E* pml4e = (pml4 + virtualAddress.Pml4Index);
        if (!pml4e->Present) return 0;

        PDPTE* pdpt = (PDPTE*)(PhysicalToVirtual(PFN_TO_PAGE(pml4e->Pdpt)));
        const PDPTE* pdpte = (pdpt + virtualAddress.PdptIndex);
        if (!pdpte->Present) return 0;
        if (pdpte->PageSize) return 0;

        PDE* pd = (PDE*)(PhysicalToVirtual(PFN_TO_PAGE(pdpte->Pd)));
        const PDE* pde = (pd + virtualAddress.PdIndex);
        if (!pde->Present) return 0;
        if (pde->PageSize) return 0;

        PTE* pt = (PTE*)(PhysicalToVirtual(PFN_TO_PAGE(pde->Pt)));
        PTE* pte = (pt + virtualAddress.PtIndex);
        if (!pte->Present) return 0;

        return pte;
    }

    // Initialize memory management structures
    NTSTATUS InitializeMemoryManagement() {
        for (UINT32 i = 0; i < 64; i++) {
            PHYSICAL_ADDRESS maxAddress;
            maxAddress.QuadPart = MAXULONG64;

            // Allocate contiguous memory for page mapping
            PageList[i].VirtualAddress = MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
            if (!PageList[i].VirtualAddress) return STATUS_PROCEDURE_NOT_FOUND;

            // Get PTE for the allocated page
            PageList[i].PTE = MemoryGetPte((ULONG64)(PageList[i].VirtualAddress));
            if (!PageList[i].PTE) return STATUS_PROCEDURE_NOT_FOUND;
        }
        return STATUS_SUCCESS;
    }

    // Read from physical memory using page remapping
    VOID ReadPhysicalAddress(UINT32 Index, ULONG64 phy, PVOID buffer, SIZE_T size) {
        _PAGE* pageInfo = &PageList[Index];
        const ULONG64 OldPFN = pageInfo->PTE->PFN;

        _disable();
        // Remap page to target physical address
        pageInfo->PTE->PFN = phy >> PAGE_SHIFT;
        __invlpg(reinterpret_cast<PVOID>(pageInfo->VirtualAddress));

        // Copy data from remapped page
        __movsb((PUCHAR)buffer, (PUCHAR)pageInfo->VirtualAddress + (phy & 0xFFF), size);

        // Restore original mapping
        pageInfo->PTE->PFN = OldPFN;
        __invlpg(reinterpret_cast<PVOID>(pageInfo->VirtualAddress));
        _enable();
    }

    // Translate virtual address to physical address using CR3
    ULONG64 TransformationCR3(UINT32 Index, ULONG64 cr3, ULONG64 VirtualAddress) {
        cr3 &= ~0xf;
        ULONG64 PAGE_OFFSET = VirtualAddress & ~(~0ul << 12);
        ULONG64 a = 0, b = 0, c = 0;

        // Walk page tables using physical memory reads
        ReadPhysicalAddress(Index, (cr3 + 8 * ((VirtualAddress >> 39) & (0x1ffll))), &a, sizeof(a));
        if (~a & 1) return 0;

        ReadPhysicalAddress(Index, ((a & ((~0xfull << 8) & 0xfffffffffull)) + 8 *
            ((VirtualAddress >> 30) & (0x1ffll))), &b, sizeof(b));
        if (~b & 1) return 0;
        if (b & 0x80) return (b & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

        ReadPhysicalAddress(Index, ((b & ((~0xfull << 8) & 0xfffffffffull)) + 8 *
            ((VirtualAddress >> 21) & (0x1ffll))), &c, sizeof(c));
        if (~c & 1) return 0;
        if (c & 0x80) return (c & ((~0xfull << 8) & 0xfffffffffull)) + (VirtualAddress & ~(~0ull << 21));

        ULONG64 address = 0;
        ReadPhysicalAddress(Index, ((c & ((~0xfull << 8) & 0xfffffffffull)) + 8 *
            ((VirtualAddress >> 12) & (0x1ffll))), &address, sizeof(address));
        address &= ((~0xfull << 8) & 0xfffffffffull);
        if (!address) return 0;

        return address + PAGE_OFFSET;
    }
}

// Registry callback function
NTSTATUS Callback(PVOID a1, PVOID a2, PVOID a3) {
    UNREFERENCED_PARAMETER(a1);
    if (a2 == NULL || a3 == NULL) return STATUS_UNSUCCESSFUL;

    NTSTATUS Status = STATUS_SUCCESS;
    REG_NOTIFY_CLASS Notify = (REG_NOTIFY_CLASS)(ULONG64)a2;

    switch (Notify) {
    case RegNtSetValueKey: {
        PREG_SET_VALUE_KEY_INFORMATION RegInfo = reinterpret_cast<PREG_SET_VALUE_KEY_INFORMATION>(a3);

        // Check if this is our driver communication
        if (RegInfo->Type == REG_BINARY && RegInfo->DataSize == sizeof(Driver)) {
            PDriver InputData = reinterpret_cast<PDriver>(RegInfo->Data);

            if (KeGetCurrentIrql() != PASSIVE_LEVEL) return STATUS_UNSUCCESSFUL;

            switch (InputData->flag) {
            case READ: {
                // Validate parameters
                if (InputData->pid <= 0 || InputData->address <= 0 ||
                    InputData->address > 0x7FFFFFFFFFFF || InputData->size <= 0 ||
                    InputData->buffer <= 0) break;

                PEPROCESS pEProcess = NULL;
                UINT32 Index = KeGetCurrentProcessorIndex();

                // Lookup target process
                Status = PsLookupProcessByProcessIdPtr((HANDLE)InputData->pid, &pEProcess);
                if (NT_SUCCESS(Status) && pEProcess != NULL) {
                    ULONG64 TargetAddress = InputData->address;
                    SIZE_T TargetSize = InputData->size;
                    UINT64 read = 0;
                    ULONG64 CR3 = GetProcessCr3(pEProcess);

                    // Read memory page by page
                    while (TargetSize) {
                        ULONG64 PhysicalAddress = ReadPageMemory::TransformationCR3(Index, CR3, TargetAddress + read);
                        if (!PhysicalAddress) break;

                        ULONG64 ReadSize = min(PAGE_SIZE - (PhysicalAddress & 0xfff), TargetSize);
                        ReadPageMemory::ReadPhysicalAddress(Index, PhysicalAddress,
                            reinterpret_cast<PVOID>(InputData->buffer + read), ReadSize);

                        TargetSize -= ReadSize;
                        read += ReadSize;
                        if (!ReadSize) break;
                    }
                    ObDereferenceObject(pEProcess);
                }
                break;
            }

            case GETMODULE: {
                if (InputData->pid <= 0 || InputData->buffer <= 0) break;

                PEPROCESS pEProcess = NULL;
                PPEB32 PEB32 = NULL;
                PPEB64 PEB64 = NULL;
                ULONG64 ModulesBase = 0;

                Status = PsLookupProcessByProcessIdPtr((HANDLE)InputData->pid, &pEProcess);
                if (NT_SUCCESS(Status) && pEProcess != NULL) {
                    // Map user buffer
                    PMDL mdl = IoAllocateMdl((PVOID)InputData->buffer, InputData->size, 0, 0, NULL);
                    if (!mdl) break;

                    MmBuildMdlForNonPagedPool(mdl);
                    PVOID Map = MmMapLockedPages(mdl, KernelMode);
                    if (!Map) {
                        IoFreeMdl(mdl);
                        break;
                    }

                    // Switch to target process context
                    SafeCr3Switch(GetProcessCr3(pEProcess));

                    PEB32 = PsGetProcessWow64ProcessPtr(pEProcess);
                    UNICODE_STRING ModuleName;
                    RtlInitUnicodeString(&ModuleName, (PCWSTR)Map);

                    // Handle Wow64 process
                    if (PEB32 != NULL) {
                        PLIST_ENTRY32 ListEntryStart32 = (PLIST_ENTRY32)(((PEB_LDR_DATA32*)PEB32->Ldr)->InMemoryOrderModuleList.Flink);
                        PLIST_ENTRY32 ListEntryEnd32 = ListEntryStart32;

                        do {
                            PLDR_DATA_TABLE_ENTRY32 LdrDataEntry32 = (PLDR_DATA_TABLE_ENTRY32)CONTAINING_RECORD(
                                ListEntryStart32, LDR_DATA_TABLE_ENTRY32, InMemoryOrderLinks);

                            UNICODE_STRING QueryModuleName = { 0 };
                            RtlInitUnicodeString(&QueryModuleName, (PWCHAR)LdrDataEntry32->BaseDllName.Buffer);

                            if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE)) {
                                ModulesBase = (ULONG64)LdrDataEntry32->DllBase;
                                __movsb((PUCHAR)Map, (PUCHAR)&ModulesBase, sizeof(ModulesBase));
                                break;
                            }
                            ListEntryStart32 = (PLIST_ENTRY32)ListEntryStart32->Flink;
                        } while (ListEntryStart32 != ListEntryEnd32);
                    }
                    else {
                        // Handle native process
                        PEB64 = PsGetProcessPebPtr(pEProcess);
                        PLIST_ENTRY64 ListEntryStart64 = (PLIST_ENTRY64)(((PEB_LDR_DATA64*)PEB64->Ldr)->InMemoryOrderModuleList.Flink);
                        PLIST_ENTRY64 ListEntryEnd64 = ListEntryStart64;

                        do {
                            PLDR_DATA_TABLE_ENTRY64 LdrDataEntry64 = (PLDR_DATA_TABLE_ENTRY64)CONTAINING_RECORD(
                                ListEntryStart64, LDR_DATA_TABLE_ENTRY64, InMemoryOrderLinks);

                            UNICODE_STRING QueryModuleName = { 0 };
                            RtlInitUnicodeString(&QueryModuleName, (PWCHAR)LdrDataEntry64->BaseDllName.Buffer);

                            if (RtlEqualUnicodeString(&ModuleName, &QueryModuleName, TRUE)) {
                                ModulesBase = (ULONG64)LdrDataEntry64->DllBase;
                                __movsb((PUCHAR)Map, (PUCHAR)&ModulesBase, sizeof(ModulesBase));
                                break;
                            }
                            ListEntryStart64 = (PLIST_ENTRY64)ListEntryStart64->Flink;
                        } while (ListEntryStart64 != ListEntryEnd64);
                    }

                    // Restore original context
                    SafeCr3Switch(GetProcessCr3(pEProcess));
                    StealthZeroMemory(&ModulesBase, sizeof(ModulesBase));

                    MmUnmapLockedPages(Map, mdl);
                    IoFreeMdl(mdl);
                }
                break;
            }
            default:
                break;
            }
        }
        break;
    }
    default:
        break;
    }
    return Status;
}

// Driver unload routine
extern "C" VOID DriverUnload(PDRIVER_OBJECT pDriver) {
    UNREFERENCED_PARAMETER(pDriver);
    CmUnRegisterCallback(Cookie);
}

// Driver entry point
extern "C" NTSTATUS RealDriverMain(PDRIVER_OBJECT pDriver, PUNICODE_STRING path) {
    if (pDriver == NULL || path == NULL) return STATUS_INVALID_PARAMETER;
    UNREFERENCED_PARAMETER(path);
    UNREFERENCED_PARAMETER(pDriver);

    // Resolve required function pointers
    UNICODE_STRING NotExportedFunctionAddress = { 0 };
    RtlInitUnicodeString(&NotExportedFunctionAddress, L"PsGetProcessWow64Process");
    PsGetProcessWow64ProcessPtr = (PPS_GET_PROCESS_WOW64_PROCESS)MmGetSystemRoutineAddress(&NotExportedFunctionAddress);

    RtlInitUnicodeString(&NotExportedFunctionAddress, L"PsGetProcessPeb");
    PsGetProcessPebPtr = (PPS_GET_PROCESS_PEB)MmGetSystemRoutineAddress(&NotExportedFunctionAddress);

    RtlInitUnicodeString(&NotExportedFunctionAddress, L"PsLookupProcessByProcessId");
    PsLookupProcessByProcessIdPtr = (PPS_LOOKUP_PROCESS_BY_PROCESS_ID)MmGetSystemRoutineAddress(&NotExportedFunctionAddress);

    RtlInitUnicodeString(&NotExportedFunctionAddress, L"MmGetVirtualForPhysical");
    MmGetVirtualForPhysicalPtr = (PMM_GET_VIRTUAL_FOR_PHYSICAL)MmGetSystemRoutineAddress(&NotExportedFunctionAddress);

    StealthZeroMemory(&NotExportedFunctionAddress, sizeof(NotExportedFunctionAddress));
    pDriver->DriverUnload = DriverUnload;

    // Register registry callback
    NTSTATUS Status = STATUS_SUCCESS;
    UNICODE_STRING altitude = { 0 };
    RtlInitUnicodeString(&altitude, L"321000");
    Status = CmRegisterCallbackEx((PEX_CALLBACK_FUNCTION)Callback, &altitude, pDriver, NULL, &Cookie, NULL);
    StealthZeroMemory(&altitude, sizeof(altitude));

    if (!NT_SUCCESS(Status)) return STATUS_FAILED_DRIVER_ENTRY;

    // Initialize memory management
    if (ReadPageMemory::InitializeMemoryManagement() == STATUS_PROCEDURE_NOT_FOUND) {
        return STATUS_PROCEDURE_NOT_FOUND;
    }

    // Verify all required functions are resolved
    if (PsLookupProcessByProcessIdPtr == NULL || PsGetProcessWow64ProcessPtr == NULL ||
        PsGetProcessPebPtr == NULL || MmGetVirtualForPhysicalPtr == NULL) {
        return STATUS_UNSUCCESSFUL;
    }

    return STATUS_SUCCESS;
}