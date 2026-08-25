# Maxado Injector

> Native Windows handle hijacking and DLL injection using direct NTAPI calls — no `OpenProcess(PROCESS_ALL_ACCESS)` dependency, no Win32 wrapper reliance.

---

## 📌 How It Works

Instead of opening the target process directly, HandleHijack Injector enumerates every process handle in the system using `NtQuerySystemInformation`, duplicates valid handles from privileged processes, and reuses an existing handle that already references the target process.

Once a usable handle is obtained, the injector:

1. Resolves the target process (PID or name)
2. Hijacks an existing process handle
3. Allocates memory inside the target
4. Writes the DLL path
5. Executes `LoadLibraryA` through `NtCreateThreadEx`
6. Falls back to APC injection if thread creation fails

The entire workflow stays close to native Windows APIs by resolving NT functions directly from **ntdll.dll**.

---

## 🧠 Architecture

```text
┌──────────────────────────────────────────────┐
│              main() / CLI Interface          │
│  Process Name / PID  •  DLL Path Input       │
└──────────────────────┬───────────────────────┘
                       │
┌──────────────────────▼───────────────────────┐
│          HandleHijackInjector Class          │
│  Validation • Process Discovery • Workflow   │
└──────────────────────┬───────────────────────┘
                       │
        ┌──────────────┴──────────────┐
        │                             │
┌───────▼────────┐           ┌────────▼────────┐
│ Handle Hijack  │           │ Injection Engine │
│ NtQuerySystem  │           │ NtCreateThreadEx │
│ NtDuplicateObj │           │ QueueUserAPC     │
└────────────────┘           └──────────────────┘
```

### Core Components

| Component | Purpose |
|-----------|---------|
| `GetProcessIdByName()` | Resolve PID from executable |
| `HijackExistingHandle()` | Enumerate & duplicate process handles |
| `EnableAllPrivileges()` | Enable required NT privileges |
| `InjectWithNtCreateThreadEx()` | Primary DLL execution |
| `InjectWithQueueUserAPC()` | Fallback execution method |
| `HandleHijackInjector::Inject()` | Complete injection pipeline |

---

## 📄 Handle Hijacking

The injector avoids relying on a direct `OpenProcess` against the target.

```cpp
NtQuerySystemInformation(
    SystemHandleInformation,
    handleTable,
    size,
    nullptr
);

NtDuplicateObject(
    sourceProcess,
    sourceHandle,
    NtCurrentProcess,
    &duplicated,
    0,0,
    DUPLICATE_SAME_ACCESS
);
```

Every duplicated handle is validated until one references the requested target process.

---

## 🔬 Injection Pipeline

```text
Target Process
      │
      ▼
Hijack Existing Handle
      │
      ▼
VirtualAllocEx
      │
      ▼
WriteProcessMemory
      │
      ▼
LoadLibraryA Address
      │
      ▼
NtCreateThreadEx
      │
   (Fail?)
      │
      ▼
QueueUserAPC
```

The injector automatically frees allocated memory and closes hijacked handles after execution.

---

## Features

- Native NTAPI implementation
- Handle hijacking instead of direct process opening
- Process lookup by PID or executable name
- Automatic privilege enabling
- Full DLL path resolution
- `NtCreateThreadEx` execution
- Support Latest BlueStacks
---

## 🧪 NTAPI Usage

Resolved dynamically from **ntdll.dll** at runtime.

| API | Purpose |
|------|---------|
| `NtQuerySystemInformation` | Enumerate system handles |
| `NtDuplicateObject` | Duplicate foreign handles |
| `NtOpenProcess` | Open source processes |
| `NtCreateThreadEx` | Native remote thread creation |
| `RtlAdjustPrivilege` | Enable required privileges |

No static imports for these native functions.

---

Compile the project normally with the Windows SDK.

---

## Usage

Launch the executable and provide:

```text
Process : notepad.exe
DLL     : C:\DLLs\Example.dll
```

The injector accepts either a process name or a numeric PID.

---

## Project Structure

```text
Maxado Injector/
│
├── main.cpp
└── README.md
```

## 📌 Credits

**Developed by Maxado God**
