#include "Inject.h"


//////////////////////////////////////////////////////////////////////////
// Helper functions.
//////////////////////////////////////////////////////////////////////////
BOOLEAN is_xxx_dll(PUNICODE_STRING FullImageName, UNICODE_STRING DllName)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC FullImageName: %wZ\n", &FullImageName);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC DllName: %wZ\n", &DllName);
	BOOLEAN ret = FALSE;

	// Pointer to the start of the FullImageName buffer
	PWCHAR fullImageNameBuffer = FullImageName->Buffer;
	USHORT fullImageNameLength = FullImageName->Length / sizeof(WCHAR);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC fullImageNameBuffer: %s\tlength=%d\n", fullImageNameBuffer, fullImageNameLength);
	// Iterate through FullImageName to find the substring
	for (USHORT i = 0; i <= fullImageNameLength - DllName.Length / sizeof(WCHAR); i++) {
		UNICODE_STRING subString;
		subString.Buffer = &fullImageNameBuffer[i];
		subString.Length = DllName.Length;
		subString.MaximumLength = DllName.Length;

		// Compare substring at current position
		if (RtlCompareUnicodeString(&subString, &DllName, TRUE) == 0) {
			DbgPrint("APC Found ntdll.dll in FullImageName\n");
			// Add your injection logic here
			return TRUE;
		}
	}
	
	if (!ret) {
		DbgPrint("APC ntdll.dll not found in FullImageName, skipping.\n");
	}
	return ret;
}

PVOID
NTAPI
RtlxFindExportedRoutineByName(
	_In_ PVOID DllBase,
	_In_ PANSI_STRING ExportName
)
{
	//
	// Borrowed from ReactOS.
	// Note that this function is not exported by ntoskrnl until Win10.
	//

	PULONG NameTable;
	PUSHORT OrdinalTable;
	PIMAGE_EXPORT_DIRECTORY ExportDirectory;
	LONG Low = 0, Mid = 0, High, Ret;
	USHORT Ordinal;
	PVOID Function;
	ULONG ExportSize;
	PULONG ExportTable;

	//
	// Get the export directory.
	//

	ExportDirectory = RtlImageDirectoryEntryToData(DllBase,
		TRUE,
		IMAGE_DIRECTORY_ENTRY_EXPORT,
		&ExportSize);

	if (!ExportDirectory)
	{
		return NULL;
	}

	//
	// Setup name tables.
	//

	NameTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNames);
	OrdinalTable = (PUSHORT)((ULONG_PTR)DllBase + ExportDirectory->AddressOfNameOrdinals);

	//
	// Do a binary search.
	//

	High = ExportDirectory->NumberOfNames - 1;
	while (High >= Low)
	{
		//
		// Get new middle value.
		//

		Mid = (Low + High) >> 1;

		//
		// Compare name.
		//

		Ret = strcmp(ExportName->Buffer, (PCHAR)DllBase + NameTable[Mid]);
		if (Ret < 0)
		{
			//
			// Update high.
			//
			High = Mid - 1;
		}
		else if (Ret > 0)
		{
			//
			// Update low.
			//
			Low = Mid + 1;
		}
		else
		{
			//
			// We got it.
			//
			break;
		}
	}

	//
	// Check if we couldn't find it.
	//

	if (High < Low)
	{
		return NULL;
	}

	//
	// Otherwise, this is the ordinal.
	//

	Ordinal = OrdinalTable[Mid];

	//
	// Validate the ordinal.
	//

	if (Ordinal >= ExportDirectory->NumberOfFunctions)
	{
		return NULL;
	}

	//
	// Resolve the address and write it.
	//

	ExportTable = (PULONG)((ULONG_PTR)DllBase + ExportDirectory->AddressOfFunctions);
	Function = (PVOID)((ULONG_PTR)DllBase + ExportTable[Ordinal]);

	//
	// We found it!
	//

	NT_ASSERT(
		(Function < (PVOID)ExportDirectory) ||
		(Function > (PVOID)((ULONG_PTR)ExportDirectory + ExportSize))
	);

	return Function;
}

NTSTATUS
NTAPI
InjDrvQueueApc(
	_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	DbgPrint("APC InjDrvQueueApc entry");
	//
	// Allocate memory for the KAPC structure.
	//

	PKAPC Apc = ExAllocatePoolWithTag(NonPagedPoolNx,
		sizeof(KAPC),
		INJ_MEMORY_TAG);

	if (!Apc)
	{
		DbgPrint("APC Apc struct allocate memory failed");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	//
	// Initialize and queue the UserMode APC.
	//

	KeInitializeApc(Apc,                                  // Apc
		PsGetCurrentThread(),                 // Thread
		OriginalApcEnvironment,               // Environment
		&InjDrvApcKernelRoutine,          // KernelRoutine
		NULL,                                 // RundownRoutine
		NormalRoutine,                        // NormalRoutine
		ApcMode,                              // ApcMode
		NormalContext);                       // NormalContext

	BOOLEAN Inserted = KeInsertQueueApc(Apc,              // Apc
		SystemArgument1,  // SystemArgument1
		SystemArgument2,  // SystemArgument2
		0);               // Increment

	if (!Inserted)
	{
		DbgPrint("APC Inserte APC failed");
		ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
		return STATUS_THREAD_IS_TERMINATING;
	}

	return STATUS_SUCCESS;
}

VOID
NTAPI
InjDrvApcNormalRoutine(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
)
{
	DbgPrint("APC Start InjDrvApcNormalRoutine");
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	Inject_DLL_Info_Global* pInjectionInfo = NormalContext;
	DbgPrint("APC Start InjInject");
	InjInject(pInjectionInfo);
	DbgPrint("APC end InjInject");
}

VOID
NTAPI
InjDrvApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
)
{
	UNREFERENCED_PARAMETER(NormalRoutine);
	UNREFERENCED_PARAMETER(NormalContext);
	UNREFERENCED_PARAMETER(SystemArgument1);
	UNREFERENCED_PARAMETER(SystemArgument2);

	//
	// Common kernel routine for both user-mode and
	// kernel-mode APCs queued by the InjpQueueApc
	// function.  Just release the memory of the APC
	// structure and return back.
	//

	ExFreePoolWithTag(Apc, INJ_MEMORY_TAG);
}

NTSTATUS
NTAPI
InjInject(
	_In_ Inject_DLL_Info_Global* pInjectionInfo
)
{
	NTSTATUS Status;

	//
	// Create memory space for injection-specific data,
	// such as path to the to-be-injected DLL.  Memory
	// of this section will be eventually mapped to the
	// injected process.
	//
	// Note that this memory is created using sections
	// instead of ZwAllocateVirtualMemory, mainly because
	// function ZwProtectVirtualMemory is not exported
	// by ntoskrnl.exe until Windows 8.1.  In case of
	// sections, the effect of memory protection change
	// is achieved by remaping the section with different
	// protection type.
	//

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
		NULL,
		OBJ_KERNEL_HANDLE,
		NULL,
		NULL);

	HANDLE SectionHandle;
	SIZE_T SectionSize = PAGE_SIZE;
	LARGE_INTEGER MaximumSize;
	MaximumSize.QuadPart = SectionSize;
	Status = ZwCreateSection(&SectionHandle,
		GENERIC_READ | GENERIC_WRITE,
		&ObjectAttributes,
		&MaximumSize,
		PAGE_EXECUTE_READWRITE,
		SEC_COMMIT,
		NULL);

	if (!NT_SUCCESS(Status))
	{
		DbgPrint("APC ZwCreateSection failed");
		return Status;
	}

	{
		NTSTATUS Status;

		PVOID SectionMemoryAddress = NULL;
		Status = ZwMapViewOfSection(SectionHandle,
			ZwCurrentProcess(),
			&SectionMemoryAddress,
			0,
			PAGE_SIZE,
			NULL,
			&SectionSize,
			ViewUnmap,
			0,
			PAGE_READWRITE);

		if (!NT_SUCCESS(Status))
		{
			DbgPrint("APC ZwMapViewOfSection failed");
			goto Exit;
		}

		//
		// Create the UNICODE_STRING structure and fill out the
		// full path of the DLL.
		//

		PUNICODE_STRING DllName = (PUNICODE_STRING)(SectionMemoryAddress);
		PWCHAR DllNameBuffer = (PWCHAR)((PUCHAR)DllName + sizeof(UNICODE_STRING));
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC Inject DllName: %wZ\n", &DllName);
		RtlCopyMemory(DllNameBuffer,
			g_inject_data.DllPathX64.Buffer,
			g_inject_data.DllPathX64.MaximumLength);

		RtlInitUnicodeString(DllName, DllNameBuffer);

		Status = InjDrvQueueApc(UserMode,
			(PKNORMAL_ROUTINE)(ULONG_PTR)pInjectionInfo->LdrLoadDllX64,
			NULL,     // Translates to 1st param. of LdrLoadDll (SearchPath)
			NULL,     // Translates to 2nd param. of LdrLoadDll (DllCharacteristics)
			DllName); // Translates to 3rd param. of LdrLoadDll (DllName)

		//
		// 4th param. of LdrLoadDll (BaseAddress) is actually an output parameter.
		//
		// When control is transferred to the KiUserApcDispatcher routine of the
		// 64-bit ntdll.dll, the RSP points to the CONTEXT structure which might
		// be eventually provided to the ZwContinue function (in case this APC
		// dispatch will be routed to the Wow64 subsystem).
		//
		// Also, the value of the RSP register is moved to the R9 register before
		// calling the KiUserCallForwarder function.  The KiUserCallForwarder
		// function actually passes this value of the R9 register down to the
		// NormalRoutine as a "hidden 4th parameter".
		//
		// Because LdrLoadDll writes to the provided address, it'll actually
		// result in overwrite of the CONTEXT.P1Home field (the first field of
		// the CONTEXT structure).
		//
		// Luckily for us, this field is only used in the very early stage of
		// the APC dispatch and can be overwritten without causing any troubles.
		//
		// For excellent explanation, see:
		// https://www.sentinelone.com/blog/deep-hooks-monitoring-native-execution-wow64-applications-part-2
		//

	Exit:
		return Status;
	}

	ZwClose(SectionHandle);

	if (NT_SUCCESS(Status))
	{
		//
		// Sets CurrentThread->ApcState.UserApcPending to TRUE.
		// This causes the queued user APC to be triggered immediately
		// on next transition of this thread to the user-mode.
		//
		KeTestAlertThread(UserMode);
	}

	return Status;
}

VOID
NTAPI
InjLoadImageNotifyRoutine(
	_In_opt_ PUNICODE_STRING FullImageName,
	_In_ HANDLE ProcessId,
	_In_ PIMAGE_INFO ImageInfo
)
{
	DbgPrint("APC InjLoadImageNotifyRoutine Entry");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "Apc FullImageName: %wZ\n", FullImageName);
	
	//
	// only inject for target process
	//
	PEPROCESS Process;
	NTSTATUS Status = PsLookupProcessByProcessId(ProcessId, &Process);
	if (!NT_SUCCESS(Status)) {
		DbgPrint("APC can't get current process info");
		return;
	}

	// Get process name from current process
	PCHAR ProcessName = PsGetProcessImageFileName(Process);
	if (ProcessName == NULL) {
		DbgPrint("APC Failed to get ProcessName");
		return;
	}
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC Current ProcessName is: %s\n", ProcessName);

	// Initialize target process name substring to match
	PCHAR TargetName = "Target";  // Adjust this string as needed

	// Check if the current ProcessName contains the target name (case-sensitive)
	if (strstr(ProcessName, TargetName) != NULL) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC ProcessName matches TargetProcessName substring.\n");
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC ProcessName does not match TargetProcessName substring.\n");
		return;
	}

	//
	// get ldr
	//
	 // Define the substring "System32\\ntdll.dll" as a UNICODE_STRING
	UNICODE_STRING ntdllSubstring = RTL_CONSTANT_STRING(L"System32\\ntdll.dll");
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "APC ntdll: %wZ\n", &ntdllSubstring);
	if (is_xxx_dll(FullImageName, ntdllSubstring) != NULL)
	{
		DbgPrint("APC Start get LdrLoadDllx64 adress");
		g_inject_data.LdrLoadDllX64 = RtlxFindExportedRoutineByName(ImageInfo->ImageBase,
			&LdrLoadDllRoutineName);
		if (!g_inject_data.LdrLoadDllX64) {
			DbgPrint("APC RtlxFindExportedRoutineByName failed, won't inject");
		}
	}
	DbgPrint("APC is_xxx_dll finished");
	if (g_inject_data.LdrLoadDllX64) {
		{
			//
			// All necessary DLLs are loaded - perform the injection.
			//
			// Note that injection is done via kernel-mode APC, because
			// InjInject calls ZwMapViewOfSection and MapViewOfSection
			// might be already on the callstack.  Because MapViewOfSection
			// locks the EPROCESS->AddressCreationLock, we would be risking
			// deadlock by calling InjInject directly.
			//
			DbgPrint("APC Start APC inject");
			InjDrvQueueApc(KernelMode,
				&InjDrvApcNormalRoutine,
				&g_inject_data,
				NULL,
				NULL);

			//
			// Mark that this process is injected.
			//

			g_inject_data.IsInjected = TRUE;
		}
		DbgPrint("APC get LdrLoadDllx64 adress Success");
	}

	////
	//// Check it is target process
	////
	//UNICODE_STRING targetFileName = RTL_CONSTANT_STRING(L"TargetProcess.exe");
	//PWSTR fullImageNameBuffer = FullImageName->Buffer;

	//// Compare only the filename portion
	//if (FullImageName == NULL ||!is_xxx_dll(FullImageName, &targetFileName)) {
	//	return;
	//}
	//
}


NTSTATUS InitializeInjectDllInfo() {
	WCHAR DllPathX64Buffer[128];
	UNICODE_STRING DllPathX64;
	DllPathX64.Length = 0;
	DllPathX64.MaximumLength = sizeof(DllPathX64Buffer);
	DllPathX64.Buffer = DllPathX64Buffer;

	// copy data
	wcscpy(DllPathX64.Buffer, L"C:\\Users\\\DebugMan_W\\Desktop\\TestDll.dll");

	// update length
	DllPathX64.Length = wcslen(DllPathX64.Buffer) * sizeof(WCHAR);

	g_inject_data.IsInjected = FALSE;
	g_inject_data.DllPathBufferX64 = ExAllocatePoolWithTag(NonPagedPoolNx,
		DllPathX64.MaximumLength,
		INJ_MEMORY_TAG);

	if (!g_inject_data.DllPathBufferX64)
	{
		ExFreePoolWithTag(g_inject_data.DllPathBufferX64, INJ_MEMORY_TAG);
		return STATUS_UNSUCCESSFUL;
	}

	g_inject_data.DllPathX64.Length = DllPathX64.Length;
	g_inject_data.DllPathX64.MaximumLength = DllPathX64.MaximumLength;
	g_inject_data.DllPathX64.Buffer = g_inject_data.DllPathBufferX64;

	RtlCopyMemory(g_inject_data.DllPathBufferX64,
		DllPathX64.Buffer,
		DllPathX64.MaximumLength);
	return STATUS_SUCCESS;
}

VOID
NTAPI
DriverDestroy(
	_In_ PDRIVER_OBJECT DriverObject
)
{
	UNREFERENCED_PARAMETER(DriverObject);

	PsRemoveLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);
	InjDrvDestroy();
}
VOID
NTAPI
InjDrvDestroy(
	VOID
)
{
	ExFreePoolWithTag(g_inject_data.DllPathBufferX64, INJ_MEMORY_TAG);
}

NTSTATUS
NTAPI
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	DbgPrint("APC Driver Entry");
	NTSTATUS Status = STATUS_SUCCESS;

	//Initialize inject dll info
	Status = InitializeInjectDllInfo();
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("APC InitializeInjectDllInfo failed,return");
		return Status;
	}

	//
	// Install LoadImage notification routines.
	//
	Status = PsSetLoadImageNotifyRoutine(&InjLoadImageNotifyRoutine);
	if (!NT_SUCCESS(Status))
	{
		DbgPrint("APC PsSetLoadImageNotifyRoutine failed,return");
		return Status;
	}

	DriverObject->DriverUnload = &DriverDestroy;
	DbgPrint("APC Success return");
	return STATUS_SUCCESS;
}