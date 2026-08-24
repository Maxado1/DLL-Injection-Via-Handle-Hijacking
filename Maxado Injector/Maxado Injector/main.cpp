#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <conio.h>
#include <vector>
#include <algorithm>
#include <cctype>
#include <sstream>
#include <psapi.h>

#define SeDebugPriv 20
#define SeTcbPrivilege 7
#define SeIncreaseQuotaPrivilege 8
#define SeSecurityPrivilege 8
#define SeTakeOwnershipPrivilege 9
#define SeLoadDriverPrivilege 10
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH ((NTSTATUS)0xC0000004)
#define NtCurrentProcess ( (HANDLE)(LONG_PTR) -1 ) 
#define ProcessHandleType 0x7
#define SystemHandleInformation 16 
#define STATUS_ACCESS_DENIED ((NTSTATUS)0xC0000022)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWCH   Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef struct _CLIENT_ID {
    PVOID UniqueProcess;
    PVOID UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    ULONG ProcessId;
    BYTE ObjectTypeNumber;
    BYTE Flags;
    USHORT Handle;
    PVOID Object;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG HandleCount;
    SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS(NTAPI* _NtDuplicateObject)(
    HANDLE SourceProcessHandle,
    HANDLE SourceHandle,
    HANDLE TargetProcessHandle,
    PHANDLE TargetHandle,
    ACCESS_MASK DesiredAccess,
    ULONG Attributes,
    ULONG Options
    );

typedef NTSTATUS(NTAPI* _RtlAdjustPrivilege)(
    ULONG Privilege,
    BOOLEAN Enable,
    BOOLEAN CurrentThread,
    PBOOLEAN Enabled
    );

typedef NTSTATUS(NTAPI* _NtOpenProcess)(
    PHANDLE            ProcessHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PCLIENT_ID         ClientId
    );

typedef NTSTATUS(NTAPI* _NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
    );

typedef NTSTATUS(NTAPI* _NtCreateThreadEx)(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    PVOID ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
    );

typedef NTSTATUS(NTAPI* _NtSetInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength
    );

SYSTEM_HANDLE_INFORMATION* g_hInfo = NULL;
HANDLE g_procHandle = NULL;
HANDLE g_hijackedHandle = NULL;
HANDLE g_targetProcessHandle = NULL;

void SetColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

OBJECT_ATTRIBUTES InitObjectAttributes(PUNICODE_STRING name, ULONG attributes, HANDLE hRoot, PSECURITY_DESCRIPTOR security) {
    OBJECT_ATTRIBUTES object;
    object.Length = sizeof(OBJECT_ATTRIBUTES);
    object.ObjectName = name;
    object.Attributes = attributes;
    object.RootDirectory = hRoot;
    object.SecurityDescriptor = security;
    object.SecurityQualityOfService = NULL;
    return object;
}

bool IsHandleValid(HANDLE handle) {
    return (handle && handle != INVALID_HANDLE_VALUE);
}

std::string ToLower(const std::string& str) {
    std::string result = str;
    for (size_t i = 0; i < result.length(); i++) {
        result[i] = tolower(result[i]);
    }
    return result;
}

bool IsNumeric(const std::string& str) {
    for (char c : str) {
        if (!isdigit(c)) return false;
    }
    return !str.empty();
}

DWORD GetProcessIdByName(const std::string& processName) {
    DWORD pid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            std::wstring ws(processEntry.szExeFile);
            std::string exeName(ws.begin(), ws.end());

            std::string exeNameLower = ToLower(exeName);
            std::string targetLower = ToLower(processName);

            if (exeNameLower == targetLower) {
                pid = processEntry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return pid;
}

std::string GetProcessNameById(DWORD pid) {
    std::string processName = "";
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return processName;

    PROCESSENTRY32 processEntry;
    processEntry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &processEntry)) {
        do {
            if (processEntry.th32ProcessID == pid) {
                std::wstring ws(processEntry.szExeFile);
                processName = std::string(ws.begin(), ws.end());
                break;
            }
        } while (Process32Next(snapshot, &processEntry));
    }
    CloseHandle(snapshot);
    return processName;
}

bool EnableAllPrivileges() {
    HMODULE Ntdll = GetModuleHandleA("ntdll");
    if (!Ntdll) return false;

    _RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");
    if (!RtlAdjustPrivilege) return false;

    BOOLEAN OldPriv;
    DWORD privileges[] = {
        SeDebugPriv,
        SeTcbPrivilege,
        SeIncreaseQuotaPrivilege,
        SeSecurityPrivilege,
        SeTakeOwnershipPrivilege,
        SeLoadDriverPrivilege
    };

    for (DWORD priv : privileges) {
        RtlAdjustPrivilege(priv, TRUE, FALSE, &OldPriv);
    }

    return true;
}

bool InjectWithNtCreateThreadEx(HANDLE hProcess, LPVOID pLoadLibrary, LPVOID pRemoteMemory) {
    HMODULE ntdll = GetModuleHandleA("ntdll");
    if (!ntdll) return false;

    _NtCreateThreadEx NtCreateThreadEx = (_NtCreateThreadEx)GetProcAddress(ntdll, "NtCreateThreadEx");
    if (!NtCreateThreadEx) return false;

    HANDLE hThread = NULL;
    NTSTATUS status = NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        NULL,
        hProcess,
        pLoadLibrary,
        pRemoteMemory,
        0,
        0,
        0,
        0,
        NULL
    );

    if (status != 0 || !hThread) {
        return false;
    }

    WaitForSingleObject(hThread, 30000);
    DWORD exitCode = 0;
    GetExitCodeThread(hThread, &exitCode);
    CloseHandle(hThread);

    return exitCode != 0;
}

bool InjectWithQueueUserAPC(HANDLE hProcess, LPVOID pLoadLibrary, LPVOID pRemoteMemory) {
    HANDLE hThread = NULL;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    DWORD targetPID = GetProcessId(hProcess);
    std::vector<DWORD> threadIds;

    do {
        if (te32.th32OwnerProcessID == targetPID) {
            threadIds.push_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hSnapshot, &te32));

    CloseHandle(hSnapshot);

    if (threadIds.empty()) return false;

    for (DWORD tid : threadIds) {
        hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (hThread) {
            DWORD result = QueueUserAPC((PAPCFUNC)pLoadLibrary, hThread, (ULONG_PTR)pRemoteMemory);
            if (result) {
                ResumeThread(hThread);
                CloseHandle(hThread);
                return true;
            }
            CloseHandle(hThread);
        }
    }

    return false;
}

HANDLE HijackExistingHandle(DWORD dwTargetProcessId) {
    HMODULE Ntdll = GetModuleHandleA("ntdll");
    if (!Ntdll) {
        return NULL;
    }

    _RtlAdjustPrivilege RtlAdjustPrivilege = (_RtlAdjustPrivilege)GetProcAddress(Ntdll, "RtlAdjustPrivilege");
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(Ntdll, "NtQuerySystemInformation");
    _NtDuplicateObject NtDuplicateObject = (_NtDuplicateObject)GetProcAddress(Ntdll, "NtDuplicateObject");
    _NtOpenProcess NtOpenProcess = (_NtOpenProcess)GetProcAddress(Ntdll, "NtOpenProcess");

    if (!RtlAdjustPrivilege || !NtQuerySystemInformation || !NtDuplicateObject || !NtOpenProcess) {
        return NULL;
    }

    EnableAllPrivileges();

    OBJECT_ATTRIBUTES Obj_Attribute = InitObjectAttributes(NULL, NULL, NULL, NULL);
    CLIENT_ID clientID = { 0 };

    DWORD size = sizeof(SYSTEM_HANDLE_INFORMATION);
    g_hInfo = (SYSTEM_HANDLE_INFORMATION*)new byte[size];
    ZeroMemory(g_hInfo, size);

    NTSTATUS NtRet = NULL;

    do {
        delete[] g_hInfo;
        size = (DWORD)(size * 1.5);
        try {
            g_hInfo = (PSYSTEM_HANDLE_INFORMATION)new byte[size];
        }
        catch (std::bad_alloc) {
            return NULL;
        }
        Sleep(1);
    } while ((NtRet = NtQuerySystemInformation(SystemHandleInformation, g_hInfo, size, NULL)) == STATUS_INFO_LENGTH_MISMATCH);

    if (!NT_SUCCESS(NtRet)) {
        delete[] g_hInfo;
        return NULL;
    }

    std::vector<HANDLE> foundHandles;

    for (unsigned int i = 0; i < g_hInfo->HandleCount; ++i) {
        if (!IsHandleValid((HANDLE)g_hInfo->Handles[i].Handle)) continue;
        if (g_hInfo->Handles[i].ObjectTypeNumber != ProcessHandleType) continue;
        if ((ULONG_PTR)g_hInfo->Handles[i].Handle <= 0x4) continue;

        clientID.UniqueProcess = (PVOID)(ULONG_PTR)g_hInfo->Handles[i].ProcessId;

        if (g_procHandle) CloseHandle(g_procHandle);
        g_procHandle = NULL;

        ACCESS_MASK sourceMasks[] = {
            PROCESS_DUP_HANDLE | PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION,
            PROCESS_DUP_HANDLE,
            PROCESS_ALL_ACCESS,
            PROCESS_QUERY_LIMITED_INFORMATION,
            PROCESS_QUERY_INFORMATION,
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ
        };

        bool sourceOpened = false;
        for (int j = 0; j < sizeof(sourceMasks) / sizeof(ACCESS_MASK); j++) {
            NtRet = NtOpenProcess(&g_procHandle, sourceMasks[j], &Obj_Attribute, &clientID);
            if (NT_SUCCESS(NtRet) && IsHandleValid(g_procHandle)) {
                sourceOpened = true;
                break;
            }
        }

        if (!sourceOpened) continue;

        ACCESS_MASK dupMasks[] = {
            PROCESS_ALL_ACCESS,
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
            PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ,
            PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD,
            PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_LIMITED_INFORMATION
        };

        for (int maskIdx = 0; maskIdx < sizeof(dupMasks) / sizeof(ACCESS_MASK); maskIdx++) {
            HANDLE hDupHandle = NULL;

            NtRet = NtDuplicateObject(g_procHandle, (HANDLE)g_hInfo->Handles[i].Handle,
                NtCurrentProcess, &hDupHandle,
                0, 0, DUPLICATE_SAME_ACCESS);

            if (!NT_SUCCESS(NtRet) || !IsHandleValid(hDupHandle)) {
                NtRet = NtDuplicateObject(g_procHandle, (HANDLE)g_hInfo->Handles[i].Handle,
                    NtCurrentProcess, &hDupHandle,
                    dupMasks[maskIdx], 0, 0);
            }

            if (NT_SUCCESS(NtRet) && IsHandleValid(hDupHandle)) {
                DWORD handlePID = GetProcessId(hDupHandle);
                if (handlePID == dwTargetProcessId) {
                    foundHandles.push_back(hDupHandle);
                }
                else {
                    CloseHandle(hDupHandle);
                }
            }
        }
    }

    if (g_procHandle) {
        CloseHandle(g_procHandle);
        g_procHandle = NULL;
    }
    if (g_hInfo) {
        delete[] g_hInfo;
        g_hInfo = NULL;
    }

    for (HANDLE hHandle : foundHandles) {
        HANDLE hFullHandle = NULL;
        if (DuplicateHandle(GetCurrentProcess(), hHandle, GetCurrentProcess(),
            &hFullHandle, PROCESS_ALL_ACCESS, FALSE, 0)) {
            if (IsHandleValid(hFullHandle)) {
                DWORD pid = GetProcessId(hFullHandle);
                if (pid == dwTargetProcessId) {
                    HANDLE hTestHandle = NULL;
                    if (DuplicateHandle(GetCurrentProcess(), hFullHandle, GetCurrentProcess(),
                        &hTestHandle, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, 0)) {
                        if (IsHandleValid(hTestHandle)) {
                            CloseHandle(hFullHandle);
                            for (HANDLE h : foundHandles) {
                                if (h != hTestHandle) CloseHandle(h);
                            }
                            return hTestHandle;
                        }
                        CloseHandle(hTestHandle);
                    }
                }
                CloseHandle(hFullHandle);
            }
        }
    }

    if (!foundHandles.empty()) {
        HANDLE bestHandle = foundHandles[0];
        HANDLE hFinalHandle = NULL;
        if (DuplicateHandle(GetCurrentProcess(), bestHandle, GetCurrentProcess(),
            &hFinalHandle, PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, 0)) {
            if (IsHandleValid(hFinalHandle)) {
                for (HANDLE h : foundHandles) {
                    if (h != bestHandle) CloseHandle(h);
                }
                return hFinalHandle;
            }
        }
        for (HANDLE h : foundHandles) {
            CloseHandle(h);
        }
    }

    return NULL;
}

class HandleHijackInjector {
private:
    std::string targetProcess;
    std::string dllPath;
    DWORD processId;
    HANDLE hijackedHandle;

    bool CheckDLLExists() {
        DWORD attributes = GetFileAttributesA(dllPath.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES) {
            return false;
        }
        return true;
    }

    std::string GetFullDLLPath() {
        char fullPath[MAX_PATH];
        char expandedPath[MAX_PATH];
        ExpandEnvironmentStringsA(dllPath.c_str(), expandedPath, MAX_PATH);
        if (GetFullPathNameA(expandedPath, MAX_PATH, fullPath, NULL)) {
            return std::string(fullPath);
        }
        return dllPath;
    }

    bool IsRunningAsAdmin() {
        HANDLE hToken = NULL;
        TOKEN_ELEVATION elevation;
        DWORD size = sizeof(TOKEN_ELEVATION);
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            if (GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &size)) {
                CloseHandle(hToken);
                return elevation.TokenIsElevated != 0;
            }
        }
        if (hToken) CloseHandle(hToken);
        return false;
    }

public:
    HandleHijackInjector() : processId(0), hijackedHandle(NULL) {}

    void DrawHeader() {
        SetColor(14);
        std::cout << "[+] Developed By Maxado God" << std::endl;
        SetColor(7);

        if (IsRunningAsAdmin()) {
            SetColor(10);
            std::cout << "[+] Running with administrator privileges" << std::endl;
            SetColor(7);
        }
    }

    bool Inject() {
        DrawHeader();

        SetColor(11);
        std::cout << "[+] Enter process name or pid: ";
        SetColor(7);
        std::getline(std::cin, targetProcess);

        targetProcess.erase(0, targetProcess.find_first_not_of(" \t\r\n"));
        targetProcess.erase(targetProcess.find_last_not_of(" \t\r\n") + 1);

        if (targetProcess.empty()) {
            SetColor(12);
            std::cerr << "[!] No process name or PID entered." << std::endl;
            SetColor(7);
            return false;
        }

        if (IsNumeric(targetProcess)) {
            processId = std::stoul(targetProcess);
            std::string name = GetProcessNameById(processId);
            if (name.empty()) {
                SetColor(12);
                std::cerr << "[!] Process with PID " << processId << " not found." << std::endl;
                SetColor(7);
                return false;
            }
            targetProcess = name;
        }
        else {
            processId = GetProcessIdByName(targetProcess);
            if (processId == 0) {
                SetColor(12);
                std::cerr << "[!] Process not found: " << targetProcess << std::endl;
                SetColor(7);
                return false;
            }
        }

        SetColor(11);
        std::cout << "[+] Enter dll path: ";
        SetColor(7);
        std::getline(std::cin, dllPath);

        dllPath.erase(0, dllPath.find_first_not_of(" \t\r\n"));
        dllPath.erase(dllPath.find_last_not_of(" \t\r\n") + 1);

        if (dllPath.empty()) {
            SetColor(12);
            std::cerr << "[!] No DLL path entered." << std::endl;
            SetColor(7);
            return false;
        }

        std::string fullDLLPath = GetFullDLLPath();

        if (!CheckDLLExists()) {
            SetColor(12);
            std::cerr << "[!] DLL file not found: " << dllPath << std::endl;
            SetColor(7);
            return false;
        }

        SetColor(10);
        std::cout << "[+] Process found \"" << targetProcess << "\" (" << processId << ")" << std::endl;
        SetColor(7);

        hijackedHandle = HijackExistingHandle(processId);

        if (!IsHandleValid(hijackedHandle)) {
            SetColor(12);
            std::cerr << "[!] Failed to hijack handle to target process." << std::endl;
            SetColor(7);
            return false;
        }

        size_t dllPathSize = fullDLLPath.length() + 1;
        LPVOID pRemoteMemory = VirtualAllocEx(
            hijackedHandle,
            NULL,
            dllPathSize,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );

        if (!pRemoteMemory) {
            CloseHandle(hijackedHandle);
            return false;
        }

        if (!WriteProcessMemory(hijackedHandle, pRemoteMemory, fullDLLPath.c_str(), dllPathSize, NULL)) {
            VirtualFreeEx(hijackedHandle, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hijackedHandle);
            return false;
        }

        LPVOID pLoadLibrary = (LPVOID)GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
        if (!pLoadLibrary) {
            VirtualFreeEx(hijackedHandle, pRemoteMemory, 0, MEM_RELEASE);
            CloseHandle(hijackedHandle);
            return false;
        }

        bool injectionSuccess = InjectWithNtCreateThreadEx(hijackedHandle, pLoadLibrary, pRemoteMemory);

        if (!injectionSuccess) {
            injectionSuccess = InjectWithQueueUserAPC(hijackedHandle, pLoadLibrary, pRemoteMemory);
        }

        VirtualFreeEx(hijackedHandle, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hijackedHandle);

        if (injectionSuccess) {
            SetColor(10);
            std::cout << "[+] Injection Successful!" << std::endl;
            SetColor(7);
            return true;
        }
        else {
            SetColor(12);
            std::cerr << "[!] Injection Failed!" << std::endl;
            SetColor(7);
            return false;
        }
    }
};

int main() {
    SetConsoleTitleA("Maxado Injector");
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);

    HandleHijackInjector injector;
    bool success = injector.Inject();

    SetColor(7);
    std::cout << "\nPress any key to exit...";
    _getch();

    return success ? 0 : 1;
}