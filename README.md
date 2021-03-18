# MinHook.NET

## Introduction

MinHook.NET is a pure managed C# port of the brilliant MinHook library by Tsuda Kageyu (https://github.com/TsudaKageyu/minhook).  The library has the capability of inline hooking native API calls, utilising .NET delegates for both the detoured and original function that is commonly called with the detour.

The project has attempted to keep within the simplistic spirit of the original MinHook library.

## Quick Start

Simple example demonstrating the hooking of the MessageBoxW Windows API

```c#

//PInvoke import of the MessageBoxW API from user32.dll 
[DllImport("user32.dll", SetLastError = true, CharSet= CharSet.Unicode)]
public static extern int MessageBoxW(int hWnd, String text, String caption, uint type);

//We need to declare a delegate that matches the prototype of the hooked function
[UnmanagedFunctionPointer(CharSet=CharSet.Unicode)]
delegate int MessageBoxWDelegate(IntPtr hWnd, string text, string caption, uint type);

//A variable to store the original function so that we can call
//within our detoured MessageBoxW handler
MessageBoxWDelegate MessageBoxW_orig;

//Our actual detour handler function
int MessageBoxW_Detour(IntPtr hWnd, string text, string caption, uint type){
    return MessageBoxW_orig(hWnd, "HOOKED: " + text, caption, type);
}

void ChangeMessageBoxMessage(){

    hookEngine = new HookEngine();
    MessageBoxW_orig = hookEngine.CreateHook("user32.dll", "MessageBoxW", new MessageBoxWDelegate(this.MessageBoxW_Detour));
    hookEngine.EnableHooks();

    //Call the PInvoke import to test our hook is in place
    MessageBox(IntPtr.Zero, "Text", "Caption", 0);

    hookEngine.DisableHooks();
}
```

## TOOO

* Figure out how to calculate imm length with ModRM based instructions
* When enabling hooks, enumerate threads and update thread context if any are running at the hook instructions that are being patched
* Implement unit tests

## Thanks

* The original MinHook library that this project is based on - https://github.com/TsudaKageyu/minhook
* The SharpDisasm project and Udis86 disassembler that the project is ported from -  https://github.com/spazzarama/SharpDisasm