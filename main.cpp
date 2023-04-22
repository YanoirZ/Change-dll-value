#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

using namespace std;

const int NEW_VALUE = 7;

DWORD FindProcessId(const wchar_t* processName);
uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName);

int main()
{
    DWORD pid = FindProcessId(L"GenshinImpact.exe");
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, false, pid);

    if (processHandle == nullptr)
    {
        printf("Không thể truy cập vào tiến trình\n");
        return 1;
    }

    uintptr_t baseAddress = GetModuleBaseAddress(pid, L"mhyprot.dll");

    if (!baseAddress)
    {
        printf("Không thể tìm thấy module\n");
        CloseHandle(processHandle);
        return 1;
    }
    while (true)
    {
        uintptr_t addressToWrite = baseAddress + 0x377064;
        uintptr_t addressToWrite2 = baseAddress + 0x377050;

        int newValue = NEW_VALUE;
        if (!WriteProcessMemory(processHandle, (LPVOID)addressToWrite, &newValue, sizeof(newValue), nullptr))
        {
            printf("Không thể ghi giá trị mới\n");
            CloseHandle(processHandle);
            return 1;
        }
        if (!WriteProcessMemory(processHandle, (LPVOID)addressToWrite2, &newValue, sizeof(newValue), nullptr))
        {
            printf("Không thể ghi giá trị mới\n");
            CloseHandle(processHandle);
            return 1;
        }
        Sleep(2000);
    }

    CloseHandle(processHandle);

    return 0;
}

DWORD FindProcessId(const wchar_t* processName)
{
    DWORD pid = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W processEntry;
    ZeroMemory(&processEntry, sizeof(processEntry));
    processEntry.dwSize = sizeof(processEntry);

    if (snapshot != INVALID_HANDLE_VALUE)
    {
        if (Process32FirstW(snapshot, &processEntry))
        {
            do
            {
                if (!wcscmp(processEntry.szExeFile, processName))
                {
                    pid = processEntry.th32ProcessID;
                    break;
                }
            } while (Process32NextW(snapshot, &processEntry));
        }

        CloseHandle(snapshot);
    }

    return pid;
}

uintptr_t GetModuleBaseAddress(DWORD pid, const wchar_t* moduleName)
{
    uintptr_t baseAddress = 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32W moduleEntry;
        ZeroMemory(&moduleEntry, sizeof(moduleEntry));
        moduleEntry.dwSize = sizeof(moduleEntry);

        if (Module32FirstW(snapshot, &moduleEntry))
        {
            do
            {
                if (!wcscmp(moduleEntry.szModule, moduleName))
                {
                    baseAddress = (uintptr_t)moduleEntry.modBaseAddr;
                    break;
                }
            } while (Module32NextW(snapshot, &moduleEntry));
        }

        CloseHandle(snapshot);
    }

    return baseAddress;
}
