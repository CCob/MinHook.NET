using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    public sealed class HookEngine : IDisposable {
        // Locks below protect one engine only. Do not update separate engines at the same time.
        // TODO: Add a shared gate before collecting threads or changing patches.
        const int ErrorInvalidParameter = 87;

        MemoryAllocator memoryAllocator = new MemoryAllocator();
        Dictionary<Delegate, Hook> originalHookMapping = new Dictionary<Delegate, Hook>();
        Dictionary<Delegate, Hook> detourHookMapping = new Dictionary<Delegate, Hook>();
        List<IntPtr> suspendedThreads = new List<IntPtr>();
        // Dictionary enumeration order is not guaranteed on .NET Framework.
        readonly List<Hook> hooksInCreationOrder = new List<Hook>();
        bool disposed;
        readonly ThreadContextBuffer threadContexts = new ThreadContextBuffer();

        public Func CreateHook<Func>(string dll, string function, Func detour) where Func : Delegate {

            IntPtr target = GetProcAddress(GetModuleHandle(dll), function);

            if (target == IntPtr.Zero)
                throw new EntryPointNotFoundException($"Function {function} could not be found in DLL {dll}");

            return CreateHook<Func>(target, detour); 
        }

        public Func CreateHook<Func>(IntPtr target, Func detour) where Func : Delegate {

            if(target == IntPtr.Zero || detour == null) {
                throw new ArgumentException($"target or detour cannot be null");
            }

            lock (this) {
                ThrowIfDisposed();
                if (detourHookMapping.ContainsKey(detour)) throw new ArgumentException("Detour is already registered", nameof(detour));
                MemorySlot slot = memoryAllocator.AllocateBuffer(target);
                try {
                    var hook = new Hook(target, Marshal.GetFunctionPointerForDelegate(detour), slot);
                    Func original = (Func)Marshal.GetDelegateForFunctionPointer(hook.Original, typeof(Func));
                    originalHookMapping.Add(original, hook);
                    try {
                        detourHookMapping.Add(detour, hook);
                        hooksInCreationOrder.Add(hook);
                    } catch {
                        originalHookMapping.Remove(original);
                        detourHookMapping.Remove(detour);
                        throw;
                    }
                    return original;
                } catch {
                    memoryAllocator.FreeBuffer(slot);
                    throw;
                }
            }
        }

        public void EnableHooks() {
            lock (this) {
                ThrowIfDisposed();
                foreach (Hook hook in hooksInCreationOrder) SetHookState(hook, true);
            }
        }

        public void DisableHooks() {
            lock (this) {
                ThrowIfDisposed();
                for (int i = hooksInCreationOrder.Count - 1; i >= 0; i--) SetHookState(hooksInCreationOrder[i], false);
            }
        }

        public void EnableHook(Delegate original) {
            lock (this) {
                ThrowIfDisposed();
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SetHookState(originalHookMapping[original], true);
            }
        }

        public void DisableHook(Delegate original) {
            lock (this) {
                ThrowIfDisposed();
                if (!originalHookMapping.ContainsKey(original)) {
                    throw new KeyNotFoundException("Hook not found, was this delegate create with CreateHook?");
                }

                SetHookState(originalHookMapping[original], false);
            }
        }

        void SetHookState(Hook hook, bool enable) {
            if (hook.Enabled == enable) return;
            UpdateThreadContexts(hook, enable);
        }

        void UpdateThreadContexts(Hook hook, bool enable) {
            NativeThreadResult result;
            try {
                CollectThreads();
                threadContexts.Prepare(suspendedThreads.Count, hook == null ? hooksInCreationOrder.Count : 1);
                result = threadContexts.Execute(suspendedThreads, hook, enable, hooksInCreationOrder);
                if (hook != null && result.PatchWritten != 0) hook.RecordNativePatch(enable);
            } finally {
                CloseThreadHandles();
            }
            // The native call resumes its entire suspension set before returning to the CLR.
            if (result.Status != NativeThreadStatus.Success) throw ThreadContextBuffer.CreateException(result);
        }

        void ThrowIfDisposed() {
            if (disposed) throw new ObjectDisposedException(nameof(HookEngine));
        }

        void CollectThreads() {

            //Suspending all threads when debugging causes deadlocks.
            if (Debugger.IsAttached) {
                throw new NotSupportedException("Changing hooks while a managed debugger is attached is not supported.");
            }

            // This snapshot misses threads created later. Stop new callers while changing hooks.
            // TODO: Coordinate thread creation if patching must work without that caller guarantee.
            // Finish managed enumeration and buffer growth before suspending any thread.
            using (Process currentProc = Process.GetCurrentProcess()) {
                foreach (ProcessThread thread in currentProc.Threads) {
                    using (thread) {
                        if (thread.Id == GetCurrentThreadId()) continue;
                        IntPtr handle = OpenThread(ThreadAccess.SUSPEND_RESUME | ThreadAccess.GET_CONTEXT |
                            ThreadAccess.SET_CONTEXT | ThreadAccess.QUERY_INFORMATION | ThreadAccess.SYNCHRONIZE, false, (uint)thread.Id);
                        if (handle == IntPtr.Zero) {
                            int error = Marshal.GetLastWin32Error();
                            // A destroyed thread object invalidates its previously enumerated ID.
                            if (error == ErrorInvalidParameter) continue;
                            throw new System.ComponentModel.Win32Exception(error);
                        }
                        try { suspendedThreads.Add(handle); }
                        catch { CloseHandle(handle); throw; }
                    }
                }
            }
        }

        void CloseThreadHandles() {

            int error = 0;
            foreach (IntPtr handle in suspendedThreads) {
                if (!CloseHandle(handle) && error == 0) error = Marshal.GetLastWin32Error();
            }
            suspendedThreads.Clear();
            if (error != 0) throw new System.ComponentModel.Win32Exception(error);
        }

        // Stop new calls and wait for active detours and original calls before entering here.
        // Moving IP does not fix return addresses left on a callee's stack. Do not dispose inside a detour.
        // TODO: Add call draining; saved original delegates must not be used after disposal.
        public void Dispose() {
            lock (this) {
                if (disposed) return;
                DisableHooks();
                // An original delegate can still be running in a previously disabled trampoline.
                if (hooksInCreationOrder.Count != 0) UpdateThreadContexts(null, false);
                memoryAllocator.Dispose();
                threadContexts.Dispose();
                originalHookMapping.Clear();
                detourHookMapping.Clear();
                hooksInCreationOrder.Clear();
                disposed = true;
                GC.SuppressFinalize(this);
            }
        }
    }
}
