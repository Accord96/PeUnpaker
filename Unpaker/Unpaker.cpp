#include "global.hpp"

typedef struct 
{
	const wchar_t* dll;
	const char* fn;
} HOOK_DESC;

BOOL GetProccessPeb(
	HANDLE hProcess,
	PEB* outPeb)
{
	ULONG returnLength = 0;

	PROCESS_BASIC_INFORMATION pbi;
	memset(&pbi, 0, sizeof(pbi));
	if (!NT_SUCCESS(NtQueryInformationProcess(
		hProcess,
		ProcessBasicInformation,
		&pbi, sizeof(pbi),
		&returnLength)))
	{
		return NULL;
	}

	PEB peb;
	memset(&peb, 0, sizeof(peb));
	if (!NT_SUCCESS(NtReadVirtualMemory(
		hProcess,
		pbi.PebBaseAddress,
		&peb,
		sizeof(peb),
		NULL)))
	{
		return NULL;
	}

	*outPeb = peb;
	return TRUE;
}

UINT64 GetProcessBase(
	HANDLE hProcess)
{
	PEB peb;
	if (!GetProccessPeb(hProcess, &peb))
		return NULL;

	return (UINT64)peb.ImageBaseAddress;
}

BOOL GetProcessNtHeader(
	HANDLE hProcess,
	PVOID imageBase,
	IMAGE_NT_HEADERS64* outNtHeaders
)
{
	IMAGE_DOS_HEADER dosHeader;
	memset(&dosHeader, 0, sizeof(dosHeader));
	NtReadVirtualMemory(
		hProcess,
		imageBase,
		&dosHeader,
		sizeof(dosHeader),
		NULL);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	IMAGE_NT_HEADERS64 ntHeaders;
	memset(&ntHeaders, 0, sizeof(ntHeaders));

	NtReadVirtualMemory(
		hProcess,
		(PVOID)((UINT64)imageBase + dosHeader.e_lfanew),
		&ntHeaders,
		sizeof(ntHeaders),
		NULL);
	if (ntHeaders.Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	*outNtHeaders = ntHeaders;
	return TRUE;
}

UINT64 GetProcessModules(
	HANDLE hProcess,
	PCWCHAR moduleName)
{
	PEB peb;
	if (!GetProccessPeb(hProcess, &peb))
		return NULL;

	PEB_LDR_DATA ldr;
	memset(&ldr, 0, sizeof(ldr));
	if (!NT_SUCCESS(NtReadVirtualMemory(
		hProcess,
		peb.Ldr,
		&ldr,
		sizeof(ldr),
		NULL)))
	{
		return NULL;
	}

	LIST_ENTRY* pStart = (LIST_ENTRY*)((UINT64)peb.Ldr + offsetof(PEB_LDR_DATA, InMemoryOrderModuleList));
	LIST_ENTRY currentEntry;
	LIST_ENTRY* pCurrent = ldr.InMemoryOrderModuleList.Flink;

	while (pCurrent != pStart)
	{
		if (!NT_SUCCESS(NtReadVirtualMemory(
			hProcess,
			(PVOID)pCurrent,
			&currentEntry,
			sizeof(currentEntry),
			NULL)))
			break;

		LDR_DATA_TABLE_ENTRY entry;
		memset(&entry, 0, sizeof(entry));
		PVOID entryBase = (PVOID)((UINT64)pCurrent - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
		if (!NT_SUCCESS(NtReadVirtualMemory(
			hProcess,
			entryBase,
			&entry,
			sizeof(entry),
			NULL)))
			break;

		if (entry.BaseDllName.Buffer)
		{
			PWCHAR buffer = (PWCHAR)malloc(entry.BaseDllName.Length * sizeof(wchar_t) + 4);

			if (NT_SUCCESS(NtReadVirtualMemory(
				hProcess,
				entry.BaseDllName.Buffer,
				buffer,
				entry.BaseDllName.Length,
				NULL)))
			{
				if (wcsstr(buffer, moduleName))
				{
					free(buffer);
					return (UINT64)entry.DllBase;
				}
			}

			free(buffer);
		}

		pCurrent = currentEntry.Flink;
	}

	return NULL;
}

BOOL GetProcessSectionHeader(
	HANDLE hProcess,
	UINT64 imageBase,
	WORD index,
	IMAGE_SECTION_HEADER* outSec)
{
	SIZE_T bytesRead = 0;

	IMAGE_DOS_HEADER dosHeader;
	memset(&dosHeader, 0, sizeof(dosHeader));
	NtReadVirtualMemory(
		hProcess,
		(PVOID)imageBase,
		&dosHeader,
		sizeof(dosHeader),
		&bytesRead);
	if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	DWORD peSig = 0;
	NtReadVirtualMemory(
		hProcess,
		(PVOID)(imageBase + dosHeader.e_lfanew),
		&peSig,
		sizeof(peSig),
		&bytesRead);
	if (peSig != IMAGE_NT_SIGNATURE)
		return FALSE;

	IMAGE_FILE_HEADER fileHdr;
	memset(&fileHdr, 0, sizeof(fileHdr));
	NtReadVirtualMemory(
		hProcess,
		(PVOID)(imageBase + dosHeader.e_lfanew + sizeof(DWORD)),
		&fileHdr,
		sizeof(fileHdr),
		&bytesRead);
	if (index >= fileHdr.NumberOfSections)
		return FALSE;

	UINT64 sectionHeaderAddr = imageBase
		+ dosHeader.e_lfanew
		+ sizeof(DWORD)
		+ sizeof(IMAGE_FILE_HEADER)
		+ fileHdr.SizeOfOptionalHeader;

	UINT64 secAddr = sectionHeaderAddr + (index * sizeof(IMAGE_SECTION_HEADER));
	IMAGE_SECTION_HEADER sec;
	memset(&sec, 0, sizeof(sec));
	NtReadVirtualMemory(
		hProcess,
		(PVOID)secAddr,
		&sec,
		sizeof(sec),
		&bytesRead);
	if (bytesRead != sizeof(sec))
		return FALSE;

	*outSec = sec;
	return TRUE;
}

/*
BOOL GetProcessSection(
	HANDLE hProcess,
	UINT64 imageBase,
	PCCH name,
	UINT64* sectionBase,
	UINT32* sectionSizeMemory,
	UINT32* sectionSizeFile = NULL)
{
	IMAGE_SECTION_HEADER sec;
	for (WORD i = 0; GetProcessSectionHeader(hProcess, imageBase, i, &sec); i++)
	{
		CHAR sectionName[9];
		memset(sectionName, 0, sizeof(sectionName));
		memcpy(sectionName, sec.Name, 8);

		if (!name || _stricmp(sectionName, name) == 0)
		{
			*sectionBase = imageBase + sec.VirtualAddress;
			*sectionSizeMemory = sec.Misc.VirtualSize;
			if (sectionSizeFile)
				*sectionSizeFile = sec.SizeOfRawData;
			return TRUE;
		}
	}

	return FALSE;
}

BOOL DumpSectionToFile(
	HANDLE hProcess, 
	PCCH name,
	UINT64* base,
	UINT32* size)
{
	PEB peb;
	if (!GetProccessPeb(hProcess, &peb))
		return FALSE;

	UINT64 sectionBase = 0;
	UINT32 sectionSize = 0;
	if (!GetProcessSection(hProcess, (UINT64)peb.ImageBaseAddress, name, &sectionBase, &sectionSize))
		return FALSE;

	PVOID buffer = VirtualAlloc(NULL, sectionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!buffer)
		return FALSE;

	SIZE_T bytesRead = 0;
	if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, (PVOID)sectionBase, buffer, sectionSize, &bytesRead)))
	{
		VirtualFree(buffer, sectionSize, MEM_FREE);
		return FALSE;
	}

	*base = (UINT64)buffer;
	*size = sectionSize;

	return TRUE;
}
*/

BOOL SuspendEntryPoint(
	HANDLE hProcess,
	PVOID imageBaseAddress,
	PBYTE oldBytes,
	PDWORD oldProtect)
{
	IMAGE_NT_HEADERS64 ntHeaders;
	if (!GetProcessNtHeader(
		hProcess,
		imageBaseAddress,
		&ntHeaders))
		return NULL;

	UINT64 imageBase = (UINT64)imageBaseAddress;
	PVOID entryPoint = (PVOID)(imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint);
	BYTE loop[] = { 0xEB, 0xFE };
	SIZE_T sizeProtect = sizeof(loop);
	
	SIZE_T readSize = 0;
	NTSTATUS status = NtReadVirtualMemory(
		hProcess,
		entryPoint,
		oldBytes,
		sizeof(loop),
		&readSize
	);

	if (!NT_SUCCESS(status))
		return FALSE;

	PVOID protectAddr = entryPoint;
	status = NtProtectVirtualMemory(
		hProcess,
		&protectAddr,
		&sizeProtect,
		PAGE_EXECUTE_READWRITE,
		oldProtect
	);

	if (!NT_SUCCESS(status))
		return FALSE;

	SIZE_T writeSize = 0;
	status = NtWriteVirtualMemory(
		hProcess,
		entryPoint, 
		loop,
		sizeof(loop),
		&writeSize
	);

	if (!NT_SUCCESS(status))
		return FALSE;

	return TRUE;
}

BOOL ResumeEntryPoint(
	HANDLE hProcess,
	PVOID imageBaseAddress,
	BYTE* oldBytes,
	UINT sizeBytes,
	PDWORD oldProtect)
{
	IMAGE_NT_HEADERS64 ntHeaders;
	if (!GetProcessNtHeader(
		hProcess,
		imageBaseAddress,
		&ntHeaders))
		return NULL;

	UINT64 imageBase = (UINT64)imageBaseAddress;
	PVOID entryPoint = (PVOID)(imageBase + ntHeaders.OptionalHeader.AddressOfEntryPoint);

	SIZE_T writeSize = 0;
	NTSTATUS status = NtWriteVirtualMemory(
		hProcess,
		entryPoint,
		oldBytes,
		sizeBytes,
		&writeSize
	);

	if (!NT_SUCCESS(status))
		return FALSE;

	PVOID protectAddr = entryPoint;
	SIZE_T sizeProtect = sizeBytes;
	status = NtProtectVirtualMemory(
		hProcess,
		&protectAddr,
		&sizeProtect,
		*oldProtect,
		oldProtect
	);

	if (!NT_SUCCESS(status))
		return FALSE;

	return TRUE;
}

BOOL HookProccess(
	HANDLE hProcess,
	PCWCHAR moduleName,
	PCCH procedureName)
{
	PVOID moduleBase = LoadLibraryW(moduleName);
	if (!moduleBase)
		return FALSE;

	PVOID procedure = (PVOID)GetProcAddress((HMODULE)moduleBase, procedureName);
	if (!procedure)
		return FALSE;

	BYTE loop[] = { 0xEB, 0xFE };
	SIZE_T sizeProtect = sizeof(loop);

	PVOID protectAddr = procedure;
	DWORD oldProtect = NULL;
	NTSTATUS status = NtProtectVirtualMemory(
		hProcess,
		&protectAddr,
		&sizeProtect,
		PAGE_EXECUTE_READWRITE,
		&oldProtect
	);

	if (!NT_SUCCESS(status))
		return FALSE;

	SIZE_T writeSize = 0;
	status = NtWriteVirtualMemory(
		hProcess,
		procedure,
		loop,
		sizeof(loop),
		&writeSize
	);
	if (!NT_SUCCESS(status))
		return FALSE;

	return TRUE;
}

BOOL HookList(
	HANDLE hProcess,
	const HOOK_DESC* list, 
	size_t count)
{
	for (size_t i = 0; i < count; ++i)
	{
		if (!HookProccess(hProcess, list[i].dll, list[i].fn))
		{
			return FALSE;
		}
	}
	return TRUE;
}

BOOL WaitUnpack(
	HANDLE hProcess,
	HANDLE hThread)
{
	PEB peb;
	if (!GetProccessPeb(hProcess, &peb))
		return FALSE;

	UINT64 imageBase = (UINT64)peb.ImageBaseAddress;

	IMAGE_SECTION_HEADER sec;
	for (WORD i = 0; GetProcessSectionHeader(hProcess, imageBase, i, &sec); i++)
	{
		UINT64 codePtr = 0;
		UINT64 sectionBase = imageBase + sec.VirtualAddress;

		if (sec.SizeOfRawData)
		{
			codePtr = sectionBase + sec.SizeOfRawData - 16;
		}
		else
		{
			codePtr = sectionBase + sec.Misc.VirtualSize - 0x1000;
		}

		UINT64 codeSample = 0;
		SIZE_T bytesRead = 0;
		if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, (PVOID)codePtr, &codeSample, sizeof(codeSample), &bytesRead)))
			return FALSE;

		ULONGLONG start = GetTickCount64();
		while (TRUE)
		{
			Sleep(1000);

			UINT64 readBytes = 0;

			CONTEXT context;
			memset(&context, 0, sizeof(CONTEXT));
			context.ContextFlags = CONTEXT_CONTROL;

			if (NT_SUCCESS(NtGetContextThread(hThread, &context)))
			{
				BYTE loop[] = { 0xEB, 0xFE };
				BYTE buffer[2] = { 0 };

				if (NT_SUCCESS(NtReadVirtualMemory(
					hProcess,
					(PVOID)context.Rip,
					buffer,
					sizeof(buffer),
					&bytesRead)))
				{
					if (buffer[0] == loop[0] &&
						buffer[1] == loop[1])
					{
						return TRUE;
					}
				}			
			}

			if (!NT_SUCCESS(NtReadVirtualMemory(hProcess, (PVOID)codePtr, &readBytes, sizeof(readBytes), &bytesRead)))
				return FALSE;

			if (codeSample != readBytes)
				return TRUE;

			if ((GetTickCount64() - start) > 5000)
				return TRUE;
		}
	}

	return TRUE;
}

BOOL CreateRemoteThread(
	HANDLE hProcess,
	PVOID startAddress,
	PVOID parameter)
{
	HANDLE hRemoteThread = NULL;

	//NTSTATUS status = NtCreateThreadEx(
	//	&hRemoteThread,
	//	THREAD_ALL_ACCESS,
	//	NULL,
	//	hProcess,
	//	(PUSER_THREAD_START_ROUTINE)startAddress,
	//	parameter,
	//	FALSE,
	//	0,
	//	0,
	//	0,
	//	NULL);
	//if (!NT_SUCCESS(status))
	//	return FALSE;

	hRemoteThread = CreateRemoteThreadEx(
		hProcess,
		NULL,
		0,
		(PTHREAD_START_ROUTINE)startAddress,
		parameter,
		0,
		NULL,
		NULL
	);


	LARGE_INTEGER timeout;
	timeout.QuadPart = -10LL * 10000000LL;

	NTSTATUS status = NtWaitForSingleObject(hRemoteThread, FALSE, &timeout);

	NtClose(hRemoteThread);

	if (status == STATUS_TIMEOUT)
		return FALSE;

	return TRUE;
}

LPVOID AllocateVirtualEx(
	HANDLE hProcess,
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD  flAllocationType,
	DWORD  flProtect)
{
	LPVOID baseAddress = lpAddress;
	SIZE_T regionSize = dwSize;

	NTSTATUS status = NtAllocateVirtualMemory(
		hProcess,
		&baseAddress,
		0,
		&regionSize,
		flAllocationType,
		flProtect);

	if (!NT_SUCCESS(status))
		baseAddress = 0;

	return baseAddress;
}

BOOL LdrLoadDllEx(
	HANDLE hProcess,
	HANDLE hThread,
	WCHAR* dllFullPath,
	BOOL needCreateThread)
{
	UINT64 ptrLdrLoadDll = (UINT64)GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");
	if (!ptrLdrLoadDll)
		return FALSE;

	PVOID remoteMemory = AllocateVirtualEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!remoteMemory)
		return FALSE;

	BYTE ldrLoadDllStubCall[] =
	{
		0x48, 0x83, 0xEC, 0x28,                         // sub rsp, 28h

		0x4C, 0x8D, 0x4C, 0x24, 0x20,                   // lea r9, [rsp+20h]

		0x49, 0xB8,                                     // mov r8, unicodeStr
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		0x33, 0xD2,                                     // xor edx, edx
		0x33, 0xC9,                                     // xor ecx, ecx

		0x48, 0xB8,                                     // mov rax, LdrLoadDll
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,

		0xFF, 0xD0,                                     // call rax

		0x48, 0x83, 0xC4, 0x28,                         // add rsp, 28h
		0xC3                                            // ret
	};

	struct SHELL_DATA
	{
		wchar_t dllFullPath[255];
		UNICODE_STRING unicodeDllPath;
	};

	SHELL_DATA localShellData;
	memset(&localShellData, 0, sizeof(localShellData));
	wcscpy(localShellData.dllFullPath, dllFullPath);

	localShellData.unicodeDllPath.Length = (USHORT)(wcslen(localShellData.dllFullPath) * sizeof(wchar_t));
	localShellData.unicodeDllPath.MaximumLength = (USHORT)(localShellData.unicodeDllPath.Length + 4);
	localShellData.unicodeDllPath.Buffer = (PWSTR)remoteMemory;

	*(UINT64*)&ldrLoadDllStubCall[0x0A + 1] = (UINT64)((UINT64)remoteMemory + offsetof(SHELL_DATA, unicodeDllPath));
	*(UINT64*)&ldrLoadDllStubCall[0x16 + 3] = (UINT64)ptrLdrLoadDll;

	SIZE_T numberOfBytesWritten = 0;

	if (!NT_SUCCESS(NtWriteVirtualMemory(
		hProcess,
		remoteMemory,
		&localShellData,
		sizeof(localShellData),
		&numberOfBytesWritten)))
		return FALSE;

	numberOfBytesWritten = 0;

	if (!NT_SUCCESS(NtWriteVirtualMemory(
		hProcess,
		(PVOID)((UINT64)remoteMemory + sizeof(SHELL_DATA)),
		&ldrLoadDllStubCall,
		sizeof(ldrLoadDllStubCall),
		&numberOfBytesWritten)))
		return FALSE;


	if (needCreateThread)
	{
		HANDLE hRemoteThread = CreateRemoteThreadEx(
			hProcess,
			NULL,
			0,
			(PTHREAD_START_ROUTINE)(DWORD64)((UINT64)remoteMemory + sizeof(SHELL_DATA)),
			NULL,
			0,
			NULL,
			NULL
		);

		if (hRemoteThread == INVALID_HANDLE_VALUE)
			return FALSE;

		LARGE_INTEGER timeout;
		timeout.QuadPart = -10LL * 10000000LL;

		NTSTATUS status = NtWaitForSingleObject(hRemoteThread, FALSE, &timeout);

		NtClose(hRemoteThread);

		if (status == STATUS_TIMEOUT)
			return FALSE;
	}
	else
	{
		CONTEXT context;
		memset(&context, 0, sizeof(context));
		context.ContextFlags = CONTEXT_ALL;

		if (!NT_SUCCESS(NtGetContextThread(
			hThread,
			&context)))
			return FALSE;

		context.Rip = (DWORD64)((UINT64)remoteMemory + sizeof(SHELL_DATA));

		if (!NT_SUCCESS(NtSetContextThread(hThread, &context)))
			return FALSE;

		if (!NT_SUCCESS(NtResumeThread(hThread, NULL)))
			return FALSE;
	}

	return TRUE;
}

BOOL ScanApps(
	WCHAR* appPath,
	BOOL isDll)
{
	wprintf(L"Start scan\n");

	STARTUPINFOW si;
	memset(&si, 0, sizeof(si));
	si.cb = sizeof(si);
	
	PROCESS_INFORMATION pi;
	memset(&pi, 0, sizeof(pi));

	WCHAR path[MAX_PATH];
	const WCHAR* fullPah = appPath;

	if (isDll)
	{
		memset(path, 0, sizeof(path));
		if (!GetCmdPathW(path, MAX_PATH))
			return FALSE;

		fullPah = path;
	}

	if (!CreateProcessW(fullPah, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
	{
		wprintf(L"CreateProcess failed %lu\n", GetLastError());
		return FALSE;
	}

	PEB peb;
	if (!GetProccessPeb(pi.hProcess, &peb))
		return FALSE;

	PVOID imageBaseAddress = peb.ImageBaseAddress;

	BYTE origBytes[2];
	DWORD oldProtect = 0;
	if (!SuspendEntryPoint(pi.hProcess, imageBaseAddress, origBytes, &oldProtect))
	{
		wprintf(L"SuspendEntryPoint failed\n");
		NtTerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return FALSE;
	}

	NtResumeProcess(pi.hProcess);
	Sleep(500);
	NtSuspendProcess(pi.hProcess);

	if (isDll)
		LdrLoadDllEx(pi.hProcess, pi.hThread, (WCHAR*)L"win32u.dll", TRUE);

	HOOK_DESC hooks[] = {
		{ L"ntdll.dll", "NtCreateProcess" },
		{ L"ntdll.dll", "NtCreateUserProcess" },
		{ L"ntdll.dll", "NtOpenProcess" },
		{ L"ntdll.dll", "NtWriteVirtualMemory" },
		{ L"ntdll.dll", "NtCreateThreadEx" },
		{ L"win32u.dll", "NtUserCreateWindowEx" },
		{ L"ntdll.dll", "NtRaiseHardError" },
		{ L"ntdll.dll", "RtlUserThreadStart" },
		{ L"ntdll.dll", "NtMapViewOfSectionEx" },
	};

	if (!HookList(pi.hProcess, hooks, ARRAYSIZE(hooks)))
	{
		NtTerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return FALSE;
	}

	if (!ResumeEntryPoint(pi.hProcess, imageBaseAddress, origBytes, sizeof(origBytes), &oldProtect))
	{
		wprintf(L"ResumeEntryPoint failed\n");
		NtTerminateProcess(pi.hProcess, 0);
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return FALSE;
	}

	if (!isDll)
	{
		NtResumeProcess(pi.hProcess);
		WaitUnpack(pi.hProcess, pi.hThread);
		NtSuspendProcess(pi.hProcess);
	}
	else
	{
		LdrLoadDllEx(pi.hProcess, pi.hThread, appPath, FALSE);
	
		WCHAR dllName[MAX_PATH];
		memset(dllName, 0, sizeof(dllName));
		ExtractFileNameW(appPath, dllName, MAX_PATH);
	
		ULONGLONG startTick = GetTickCount64();
		while (TRUE)
		{
			imageBaseAddress = (PVOID)GetProcessModules(pi.hProcess, dllName);
			if (imageBaseAddress)
				break;

			if (GetTickCount64() - startTick > 5000)
			{
				wprintf(L"Load dll failed\n");
				NtTerminateProcess(pi.hProcess, 0);
				CloseHandle(pi.hThread);
				CloseHandle(pi.hProcess);
				return FALSE;
			}

			Sleep(100);
		}

		NtSuspendProcess(pi.hProcess);
	}

	IMAGE_SECTION_HEADER sec;
	for (WORD i = 0; GetProcessSectionHeader(pi.hProcess, (UINT64)imageBaseAddress, i, &sec); i++)
	{
		UINT64 sectionBase = (UINT64)imageBaseAddress + sec.VirtualAddress;
		UINT32 sectionSize = sec.Misc.VirtualSize;

		PVOID buffer = VirtualAlloc(NULL, sectionSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		if (!buffer)
			continue;

		SIZE_T bytesRead = 0;
		if (!NT_SUCCESS(NtReadVirtualMemory(pi.hProcess, (PVOID)sectionBase, buffer, sectionSize, &bytesRead)))
		{
			VirtualFree(buffer, sectionSize, MEM_FREE);
			continue;
		}

		PVOID found = Sig::find<Sig::Byte<0x72, 0x65, 0x70, 0x6F, 0x73, 0x5C, 0x56, 0x61, 0x6E, 0x69, 0x73, 0x68>>(buffer, sectionSize);
		if (found)
		{
			wprintf(L"vanish detect!!!\n");
			break;
		}

		VirtualFree(buffer, sectionSize, MEM_FREE);
	}

	NtTerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	wprintf(L"End scan\n");

	return TRUE;
}

int wmain(int argc, WCHAR* argv[])
{
	ScanApps(argv[1], TRUE);
	while (TRUE);
}