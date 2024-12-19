#pragma once
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h> 

//////////////////////////////////////////////////////////////////////////
// Definitions.
//////////////////////////////////////////////////////////////////////////
#define INJ_MEMORY_TAG 'Test'



//////////////////////////////////////////////////////////////////////////
// Variables.
//////////////////////////////////////////////////////////////////////////
typedef struct _Global_Inject_DLL_Info
{
	//LIST_ENTRY      InjectionInfoListHead;

	UNICODE_STRING  DllPathX64;
	PWCHAR          DllPathBufferX64;

	PVOID LdrLoadDllX64;

	BOOLEAN     IsInjected;
} Inject_DLL_Info_Global;

Inject_DLL_Info_Global g_inject_data;

ANSI_STRING LdrLoadDllRoutineName = RTL_CONSTANT_STRING("LdrLoadDll");




//////////////////////////////////////////////////////////////////////////
// private functions
//////////////////////////////////////////////////////////////////////////
NTSTATUS
NTAPI
InjInject(
	_In_ Inject_DLL_Info_Global* pInjectionInfo
);



//////////////////////////////////////////////////////////////////////////
// Function prototypes.
//////////////////////////////////////////////////////////////////////////
/*
* OriginalApcEnvironment(default environment):APC should be executed in the target thread's original environment.
											  This means that the APC will execute in the context of the target thread,
											  regardless of whether the target thread is in the suspended, waiting, or other state.

* AttachApcEnvironment:If another thread is associated with the target thread via the KeAttachProcess or KeAttachThread function,
					   and you want to execute APC during that association, then APC should execute in AttachApcEnvironment.
					   This is often used for debugging or other situations where you need to interact deeply with another thread or process.

*CurrentApcEnvironment:The value represents the current APC environment.
					   If the current thread is associated with another thread or process via KeAttachThread or KeAttachProcess,
					   then CurrentApcEnvironment will be AttachApcEnvironment. Otherwise, it will be OriginalApcEnvironment.

*InsertApcEnvironment:This environment is used to indicate that the APC should be executed in the environment in which it is inserted.
					  In general, this is similar to OriginalApcEnvironment, but it is specifically designed for those
					  cases where an APC needs to be inserted ina specific context.
*/
typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT;

/*
*  Normal Routine
*/
typedef
VOID
(NTAPI* PKNORMAL_ROUTINE) (
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
	);

/*
*  Kernel Routine
*/
typedef
VOID
(NTAPI* PKKERNEL_ROUTINE) (
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
	);

/*
*  Rundown Routine
*/
typedef
VOID
(NTAPI* PKRUNDOWN_ROUTINE) (
	_In_ PKAPC Apc
	);

PVOID RtlImageDirectoryEntryToData(
	PVOID Base,
	BOOLEAN MappedAsImage,
	USHORT DirectoryEntry,
	PULONG Size
);


/*
*  APC Initialie function
*/
NTKERNELAPI
VOID
NTAPI
KeInitializeApc(
	_Out_ PRKAPC Apc,
	_In_ PETHREAD Thread,
	_In_ KAPC_ENVIRONMENT Environment,
	_In_ PKKERNEL_ROUTINE KernelRoutine,
	_In_opt_ PKRUNDOWN_ROUTINE RundownRoutine,
	_In_opt_ PKNORMAL_ROUTINE NormalRoutine,
	_In_opt_ KPROCESSOR_MODE ApcMode,
	_In_opt_ PVOID NormalContext
);


/*
*  APC Insert function
*/
NTKERNELAPI
BOOLEAN
NTAPI
KeInsertQueueApc(
	_Inout_ PRKAPC Apc,
	_In_opt_ PVOID SystemArgument1,
	_In_opt_ PVOID SystemArgument2,
	_In_ KPRIORITY Increment
);

NTKERNELAPI
BOOLEAN
NTAPI
KeAlertThread(
	_Inout_ PKTHREAD Thread,
	_In_ KPROCESSOR_MODE AlertMode
);

NTKERNELAPI
BOOLEAN
NTAPI
KeTestAlertThread(
	_In_ KPROCESSOR_MODE AlertMode
);

NTSTATUS
NTAPI
InjDrvQueueApc(
	_In_ KPROCESSOR_MODE ApcMode,
	_In_ PKNORMAL_ROUTINE NormalRoutine,
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

VOID
NTAPI
InjDrvApcNormalRoutine(
	_In_ PVOID NormalContext,
	_In_ PVOID SystemArgument1,
	_In_ PVOID SystemArgument2
);

VOID
NTAPI
InjDrvApcKernelRoutine(
	_In_ PKAPC Apc,
	_Inout_ PKNORMAL_ROUTINE* NormalRoutine,
	_Inout_ PVOID* NormalContext,
	_Inout_ PVOID* SystemArgument1,
	_Inout_ PVOID* SystemArgument2
);

VOID
NTAPI
InjDrvDestroy(
	VOID
);

NTKERNELAPI
NTSTATUS
NTAPI
PsLookupProcessByProcessId(
	IN  HANDLE    ProcessId,
	OUT PEPROCESS* Process
);

NTKERNELAPI
PCHAR
NTAPI
PsGetProcessImageFileName(
	_In_ PEPROCESS Process
);

