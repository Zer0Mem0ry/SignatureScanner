#pragma once

#include <iostream>
#include <string>
#include <Windows.h>
#include <TlHelp32.h>


// Better than using namespace std;

using std::cout;
using std::endl;
using std::string;

// datatype for a module in memory (dll, regular exe)
struct module
{
    DWORD64 dwBase, dwSize;
};

class SignatureScanner
{
public:
    module TargetModule;  // Hold target module
    HANDLE TargetProcess; // for target process
    DWORD  TargetId;      // for target process


    // For getting a handle to a process
    HANDLE GetProcess(const char* processName)
    {
        HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
        PROCESSENTRY32 entry;
        entry.dwSize = sizeof(entry);
        do
            if(!strcmp(entry.szExeFile, processName))
            {
                TargetId = entry.th32ProcessID;
                CloseHandle(handle);
                TargetProcess = OpenProcess(PROCESS_ALL_ACCESS, false, TargetId);
                return TargetProcess;
            }
        while(Process32Next(handle, &entry));

        return false;
    }

    // For getting information about the executing module
    module GetModule(const char* moduleName)
    {
        HANDLE hmodule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, TargetId);
        MODULEENTRY32 mEntry;
        mEntry.dwSize = sizeof(mEntry);

        do
        {
            if(!strcmp(mEntry.szModule, (LPSTR)moduleName))
            {
                CloseHandle(hmodule);

                TargetModule = { (DWORD64)mEntry.hModule, (DWORD64)mEntry.modBaseSize };
                return TargetModule;
            }
        }
        while(Module32Next(hmodule, &mEntry));

        module mod = { (DWORD_PTR)false, (DWORD_PTR)false };
        return mod;
    }

    DWORD GetProcessID(const char* ProcessName) // now returns the process ID. Why mess around with globals?
    {
        PROCESSENTRY32   pe32;
        HANDLE         hSnapshot = NULL;
        DWORD pid = 0; // initialize to impossible pid

        pe32.dwSize = sizeof(PROCESSENTRY32);
        hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        // should probably check for hSnapshot != INVALID_HANDLE_VALUE right about here
        if(Process32First(hSnapshot, &pe32))
        {
            do
            {
                if(strcmp(pe32.szExeFile, ProcessName) == 0)
                {
                    pid = pe32.th32ProcessID;
                    break;
                }
            }
            while(Process32Next(hSnapshot, &pe32));
        }

        if(hSnapshot != INVALID_HANDLE_VALUE)
            CloseHandle(hSnapshot);

        return pid;
    }

    // Basic WPM wrapper, easier to use.
    template <typename var>
    bool WriteMemory(DWORD64 Address, var Value)
    {
        return WriteProcessMemory(TargetProcess, (LPVOID)Address, &Value, sizeof(var), 0);
    }

    // Basic RPM wrapper, easier to use.
    template <typename var>
    var ReadMemory(DWORD64 Address)
    {
        var value;
        ReadProcessMemory(TargetProcess, (LPCVOID)Address, &value, sizeof(var), NULL);
        return value;
    }

    // for comparing a region in memory, needed in finding a signature
    bool MemoryCompare(const BYTE* bData, const BYTE* bMask, const char* szMask)
    {
        for(; *szMask; ++szMask, ++bData, ++bMask)
        {
            if(*szMask == 'x' && *bData != *bMask)
            {
                return false;
            }
        }
        return (*szMask == NULL);
    }

    // for finding a signature/pattern in memory of another process
    DWORD64 FindSignature(DWORD64 start, DWORD64 size, const char* sig, const char* mask)
    {
        BYTE* data = new BYTE[size];
        SIZE_T bytesRead;
        DWORD64 result = NULL;

        ReadProcessMemory(TargetProcess, (LPVOID)start, data, size, &bytesRead);

        for(DWORD64 i = 0; i < size; i++)
        {
            if(MemoryCompare((const BYTE*)(data + i), (const BYTE*)sig, mask))
            {
                result = start + i;
                break;
            }
        }
        delete[] data;
        return result;
    }
};
