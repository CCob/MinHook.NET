using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    public sealed class HookEngine : IDisposable {

        MemoryAllocator memoryAllocator = new MemoryAllocator();
        Dictionary<Delegate, Hook> originalHookMapping = new Dictionary<Delegate, Hook>();
        Dictionary<Delegate, Hook> detourHookMapping = new Dictionary<Delegate, Hook>();
        List<IntPtr> suspendedThreads = new List<IntPtr>();

        public Func CreateHook<Func>(string dll, string function, Func detour) where Func : Delegate {

            IntPtr target = GetProcAddress(GetModuleHandle(dll), function);

            if (target == IntPtr.Zero)
                throw new EntryPointNotFoundException($"Function {function} could not be found in DLL {dll}");

            lock (this) {
                var hook = new Hook(target, Marshal.GetFunctionPointerForDelegate(detour), memoryAllocator.AllocateBuffer(target));
                Func original = (Func)Marshal.GetDelegateForFunctionPointer(hook.Original, typeof(Func));
                originalHookMapping.Add(original, hook);

                //Main purpose of this is to make sure the detour delegate
                //does not get garbage collected for the lifetime of the hook
                detourHookMapping.Add(detour, hook);
                return original;
            }
        }

        public void EnableHooks() {
            foreach(var hook in originalHookMapping) {
                EnableHook(hook.Key);
            }
        }

        public void DisableHooks() {
            foreach (var hook in originalHookMapping) {
                DisableHook(hook.Key);
            }
        }

        public void EnableHook(Delegate original) {
            lock (this) {
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SuspendThreads();
                originalHookMapping[original].Enable(true);
                ResumeThreads();
            }
        }

        public void DisableHook(Delegate original) {
            lock (this) {
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SuspendThreads();
                originalHookMapping[original].Enable(false);
                ResumeThreads();
            }
        }

        void SuspendThreads() {

            //Suspending all threads when debugging causes deadlocks.
            if (Debugger.IsAttached) {
                return;
            }

            //TODO: Currently doesn't move thread IP if any of the threads
            //are executing within the location of a hook prologue at the time.
            //This will probably crash the program if that scenario happens (rare)

            Process currentProc = Process.GetCurrentProcess();

            foreach(ProcessThread thread in currentProc.Threads) {
                if(thread.Id != GetCurrentThreadId()) {                    
                    IntPtr threadHandle = OpenThread(ThreadAccess.SUSPEND_RESUME, false, (uint)thread.Id);
                    SuspendThread(threadHandle);
                    suspendedThreads.Add(threadHandle);                                       
                }             
            }
        }

        void ResumeThreads() {

            foreach(var handle in suspendedThreads) {
                ResumeThread(handle);
                CloseHandle(handle);                    
            }

            suspendedThreads.Clear();
        }

        public void Dispose() {
            DisableHooks();
            memoryAllocator.Dispose();
            GC.SuppressFinalize(this);
        }
    }
}
