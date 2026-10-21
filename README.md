# MinHook.NET

## Introduction

MinHook.NET is a C# port of MinHook by Tsuda Kageyu (https://github.com/TsudaKageyu/minhook), with .NET delegates for detours and original calls. This fork uses a small Windows x86/x64 native helper for thread suspension, instruction-pointer relocation, and patch transactions.

The project has attempted to keep within the simplistic spirit of the original MinHook library.

## Quick Start

Simple example demonstrating the hooking of the MessageBoxW Windows API

```c#
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern int MessageBoxW(IntPtr hWnd, String text, String caption, uint type);

    //We need to declare a delegate that matches the prototype of the hooked function
    [UnmanagedFunctionPointer(CallingConvention.StdCall,CharSet=CharSet.Unicode)]
    delegate int MessageBoxWDelegate(IntPtr hWnd, string text, string caption, uint type);

    //A variable to store the original function so that we can call
    //within our detoured MessageBoxW handler
    MessageBoxWDelegate MessageBoxW_orig;

    //Our actual detour handler function
    int MessageBoxW_Detour(IntPtr hWnd, string text, string caption, uint type) {
        return MessageBoxW_orig(hWnd, "HOOKED: " + text, caption, type);
    }

    void ChangeMessageBoxMessage() {

		using (HookEngine engine = new HookEngine()) {

			MessageBoxW_orig = engine.CreateHook("user32.dll", "MessageBoxW", new MessageBoxWDelegate(MessageBoxW_Detour));
			engine.EnableHooks();

			//Call the PInvoke import to test our hook is in place
			MessageBoxW(IntPtr.Zero, "Text", "Caption", 0);
		}
    }
```

## Native Hook Safety

Keep the engine alive for as long as any detour or original delegate can be called.
Stop callers and wait for in-flight calls to finish before disposing the engine.
Disabling an inline patch is not a callback-draining mechanism. A delegate returned
by `CreateHook` is invalid after its owning engine is disposed.

Layers created by one engine are disabled in reverse creation order. Disabling an
older layer while another engine or library owns the current patch is rejected
without modifying the newer patch. Remove the newer layer first, then retry.
Changes while a managed debugger is attached are rejected rather than silently
patching running threads without suspension.

Suspended threads use the same-process x86 or x64 Windows CONTEXT ABI, with aligned
native storage allocated before suspension. Enabling maps original instruction
boundaries into the trampoline; disabling maps them back, including hotpatch and
x64 relay entries and the continuations emitted by expanded CALL/Jcc instructions.
Disposal also checks previously disabled trampolines before releasing their pages.

All contexts are captured and planned before any context is changed. Failed
context writes or an unchanged patch failure trigger context rollback, and managed
exceptions are created after the suspension set is resumed. Unknown instruction
boundaries inside owned patch/trampoline regions and native failures are reported,
not rounded or silently skipped.
Rollback errors are reported as well; native access failures are not recoverable
by pretending the update succeeded.

The complete interval from first suspension to last resume runs in
`MinHook.Threads.dll`, without managed callbacks, CLR calls, or heap allocations.
Managed code prepares handles, instruction tables, and reusable native storage
before entering the helper. Tiered compilation and GC remain enabled normally.
Terminated threads are excluded only when their handle is signaled; failed
`OpenThread` calls with an invalidated thread ID are distinct from access failures.

This is not a stack walk or a callback-draining mechanism. A thread inside a
callee may still have a return address into the trampoline, and code can retain an
original delegate. Stop those callers and drain them before disposal. Independent
engines are not coordinated, and threads created after enumeration are not covered
by that enumeration. Do not modify code owned by another concurrently updating engine.

Reference algorithms: [MinHook v1.3.4 FindOldIP/FindNewIP](https://github.com/TsudaKageyu/minhook/blob/v1.3.4/src/hook.c)
and [Detours thread updates](https://github.com/microsoft/Detours/wiki/DetourUpdateThread).
Windows requires stopped threads for [GetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadcontext)
and [SetThreadContext](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-setthreadcontext).

## Regression Tests

The native regression suite uses xUnit v3 and Windows executable-memory fixtures.
No game process or UI dialog is required. Build the helper with CMake and MSVC
first, then run both process architectures with matching dotnet hosts:

```powershell
./scripts/build-native.ps1

dotnet build tests/MinHook.NET.Tests/MinHook.NET.Tests.csproj -c Release -p:TargetFrameworks=net9.0 -p:PlatformTarget=x64 -p:GeneratePackageOnBuild=false
dotnet tests/MinHook.NET.Tests/bin/x64/Release/net9.0/MinHook.NET.Tests.dll
dotnet build tests/MinHook.NET.Tests/MinHook.NET.Tests.csproj -c Release -p:TargetFrameworks=net9.0 -p:PlatformTarget=x86 -p:GeneratePackageOnBuild=false
& "${env:ProgramFiles(x86)}/dotnet/dotnet.exe" tests/MinHook.NET.Tests/bin/x86/Release/net9.0/MinHook.NET.Tests.dll
```

Native worker tests run in a child process with a 30-second deadline. They cover
real suspended OS threads, preserved stack/flags, original/trampoline migration,
hotpatch and x64 relay/CALL/Jcc continuations, previously disabled trampolines,
capture/write/patch failures, rollback, repeated concurrent enable/disable, and
simultaneous compacting GC.

The allocation tests cover warmed-up patch/restore and context capture/apply/
rollback operations, not hook creation or process-thread enumeration. Context
storage is reused and owned by the engine; its finalizable owner prevents native
buffer leaks if an engine is abandoned. Instruction encodings use stack buffers and typed
native writes: MemoryMarshal on .NET and .NET Standard, fixed pointers on .NET
Framework. There is no managed suspension fallback and no new NuGet dependency.
The helper uses the static MSVC runtime; ship the matching `MinHook.Threads.dll`
beside `MinHook.NET.dll`. NuGet packages include both native architectures under
`runtimes/win-x86/native` and `runtimes/win-x64/native`. Direct DLL references must
copy the helper explicitly, including into publish output. Missing or mismatched
native binaries fail loading rather than silently switching implementation.

An optional SDK ABI probe uses CMake/MSVC to check the declarations independently:

```powershell
cmake -S tests/ContextAbi -B artifacts/context-abi-x64 -A x64
cmake --build artifacts/context-abi-x64 --config Release
./artifacts/context-abi-x64/Release/context_abi.exe
cmake -S tests/ContextAbi -B artifacts/context-abi-x86 -A Win32
cmake --build artifacts/context-abi-x86 --config Release
./artifacts/context-abi-x86/Release/context_abi.exe
```

## TODO

* Coordinate independent engines and define thread-creation synchronization
* Define a callback-draining protocol for retained originals and pending native return addresses

## Thanks

* The original MinHook library that this project is based on - https://github.com/TsudaKageyu/minhook
* The SharpDisasm project and Udis86 disassembler that the project is ported from -  https://github.com/spazzarama/SharpDisasm
