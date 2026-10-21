using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    internal enum ContextUpdateResult { Success, CaptureFailed, UnmappedInstruction, ApplyFailed }

    // WinNT.h CONTEXT layouts, Windows SDK 10.0.26100.0. Only CONTEXT_CONTROL is requested.
    // Keep these layouts and Snapshot in sync with the native helper. Other CPU ABIs need their own layouts.
    internal sealed unsafe class ThreadContextBuffer : IDisposable {
        internal const int X86ContextSize = 716;
        internal const int X64ContextSize = 1232;
        internal const int ContextAlignment = 16;
        internal const uint X86ContextControl = 0x00010001;
        internal const uint X64ContextControl = 0x00100001;
        const ushort ProcessorArchitectureIntel = 0;
        const ushort ProcessorArchitectureAmd64 = 9;

        [StructLayout(LayoutKind.Explicit, Size = X86ContextSize)]
        internal struct Context32 {
            [FieldOffset(0)] internal uint ContextFlags;
            [FieldOffset(180)] internal uint Ebp;
            [FieldOffset(184)] internal uint Eip;
            [FieldOffset(188)] internal uint SegCs;
            [FieldOffset(192)] internal uint EFlags;
            [FieldOffset(196)] internal uint Esp;
            [FieldOffset(200)] internal uint SegSs;
        }

        [StructLayout(LayoutKind.Explicit, Size = X64ContextSize)]
        internal struct Context64 {
            [FieldOffset(48)] internal uint ContextFlags;
            [FieldOffset(56)] internal ushort SegCs;
            [FieldOffset(66)] internal ushort SegSs;
            [FieldOffset(68)] internal uint EFlags;
            [FieldOffset(152)] internal ulong Rsp;
            [FieldOffset(248)] internal ulong Rip;
        }

        struct Snapshot {
            internal IntPtr Thread;
            internal ulong OriginalIp;
            internal ulong PlannedIp;
            internal uint Suspended;
            internal uint Exited;
        }

        static readonly int ContextOffset = Align(sizeof(Snapshot));
        static readonly int SlotSize = Align(ContextOffset + (IntPtr.Size == 8 ? sizeof(Context64) : sizeof(Context32)));
        IntPtr buffer;
        IntPtr plans;
        int capacity;
        int planCapacity;
        uint appliedCount;
        bool disposed;
        internal ulong FailedInstructionPointer { get; private set; }

        internal void Prepare(int count, int hookCount = 1) {
            // Grow buffers before stopping threads. Allocation here is setup work, not part of the frozen path.
            if (disposed) throw new ObjectDisposedException(nameof(ThreadContextBuffer));
            SYSTEM_INFO info = default;
            GetSystemInfo(ref info);
            if (info.wProcessorArchitecture != (IntPtr.Size == 8 ? ProcessorArchitectureAmd64 : ProcessorArchitectureIntel))
                throw new PlatformNotSupportedException("Thread contexts support Windows x86 and x64 processes only.");
            appliedCount = 0;
            FailedInstructionPointer = 0;
            if (hookCount > planCapacity) {
                int newPlanCapacity = Math.Max(hookCount, checked(planCapacity * 2));
                IntPtr planAllocation = VirtualAlloc(IntPtr.Zero, (IntPtr)checked(newPlanCapacity * sizeof(NativeHookPlan)),
                    AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
                if (planAllocation == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
                if (plans != IntPtr.Zero && !VirtualFree(plans, 0, FreeType.Release)) {
                    int error = Marshal.GetLastWin32Error();
                    VirtualFree(planAllocation, 0, FreeType.Release);
                    throw new Win32Exception(error);
                }
                plans = planAllocation;
                planCapacity = newPlanCapacity;
            }
            if (count <= capacity) return;
            int newCapacity = Math.Max(count, checked(capacity * 2));
            int size = checked(newCapacity * SlotSize);
            IntPtr allocation = VirtualAlloc(IntPtr.Zero, (IntPtr)size,
                AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ReadWrite);
            if (allocation == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            if (buffer != IntPtr.Zero && !VirtualFree(buffer, 0, FreeType.Release)) {
                int error = Marshal.GetLastWin32Error();
                VirtualFree(allocation, 0, FreeType.Release);
                throw new Win32Exception(error);
            }
            buffer = allocation;
            capacity = newCapacity;
        }

        internal IntPtr ContextAt(int index) { return buffer + index * SlotSize + ContextOffset; }
        ref Snapshot SnapshotAt(int index) { return ref NativeMemory.AsRef<Snapshot>(buffer + index * SlotSize); }

        internal static ulong ReadIp(IntPtr context) {
            return IntPtr.Size == 8 ? NativeMemory.AsRef<Context64>(context).Rip : NativeMemory.AsRef<Context32>(context).Eip;
        }

        internal static void WriteIp(IntPtr context, ulong ip) {
            if (IntPtr.Size == 8) NativeMemory.AsRef<Context64>(context).Rip = ip;
            else NativeMemory.AsRef<Context32>(context).Eip = unchecked((uint)ip);
        }

        internal static void Initialize(IntPtr context) {
            // GetThreadContext fills all requested CONTROL fields.
            if (IntPtr.Size == 8) {
                ref Context64 value = ref NativeMemory.AsRef<Context64>(context);
                value.ContextFlags = X64ContextControl;
            } else {
                ref Context32 value = ref NativeMemory.AsRef<Context32>(context);
                value.ContextFlags = X86ContextControl;
            }
        }

        internal ContextUpdateResult CaptureAndPlan(List<IntPtr> threads, Hook hook, bool enable,
            List<Hook> disposalHooks, out int error) {
            uint hookCount = SetInputs(threads, hook, disposalHooks);
            NativeThreadMethods.mh_capture(buffer, (uint)threads.Count, plans, hookCount, enable ? 1 : 0, out var result);
            GC.KeepAlive(this);
            FailedInstructionPointer = result.FailedIp;
            error = result.Error;
            return (ContextUpdateResult)result.Status;
        }

        internal ContextUpdateResult Apply(List<IntPtr> threads, out int error, out int rollbackError) {
            NativeThreadMethods.mh_apply(buffer, (uint)threads.Count, out appliedCount, out var result);
            GC.KeepAlive(this);
            error = result.Error;
            rollbackError = result.RollbackError;
            return (ContextUpdateResult)result.Status;
        }

        internal int Rollback(List<IntPtr> threads) {
            int error = NativeThreadMethods.mh_rollback(buffer, appliedCount);
            GC.KeepAlive(this);
            appliedCount = 0;
            return error;
        }

        uint SetInputs(List<IntPtr> threads, Hook hook, List<Hook> disposalHooks) {
            int hookCount = hook == null ? disposalHooks.Count : 1;
            if (threads.Count > capacity || hookCount > planCapacity)
                throw new InvalidOperationException("Prepare context storage before setting transaction inputs.");
            for (int i = 0; i < threads.Count; i++) {
                ref Snapshot snapshot = ref SnapshotAt(i);
                snapshot.Thread = threads[i];
                snapshot.Suspended = snapshot.Exited = 0;
            }
            for (int i = 0; i < hookCount; i++) {
                ref NativeHookPlan plan = ref NativeMemory.AsRef<NativeHookPlan>(plans + i * sizeof(NativeHookPlan));
                (hook ?? disposalHooks[i]).WriteNativePlan(ref plan);
            }
            return (uint)hookCount;
        }

        internal NativeThreadResult Execute(List<IntPtr> threads, Hook hook, bool enable, List<Hook> disposalHooks) {
            uint hookCount = SetInputs(threads, hook, disposalHooks);
            NativeThreadMethods.mh_execute(buffer, (uint)threads.Count, plans, hookCount,
                enable ? 1 : 0, hook == null ? 0 : 1, out var result);
            GC.KeepAlive(this);
            return result;
        }

        internal static Exception CreateException(NativeThreadResult result) {
            // Rollback or resume can fail too. Keep those errors visible; retrying or freeing code blindly is unsafe.
            string message = "Native thread transaction failed: " + result.Status;
            if (result.RollbackError != 0) message += "; context rollback failed with Win32 error " + result.RollbackError;
            if (result.ResumeError != 0) message += "; thread resume failed with Win32 error " + result.ResumeError;
            if (result.Status == NativeThreadStatus.UnmappedInstruction)
                return new NotSupportedException(message + ". IP 0x" + result.FailedIp.ToString("X") + " is not at a known instruction boundary.");
            if (result.Status == NativeThreadStatus.PatchChanged)
                return new InvalidOperationException(message + ". Remove newer hooks before changing this hook.");
            return new Win32Exception(result.Error, message);
        }

        static int Align(int size) { return (size + ContextAlignment - 1) & -ContextAlignment; }

        void Release(bool throwing) {
            if (plans != IntPtr.Zero) {
                if (!VirtualFree(plans, 0, FreeType.Release)) {
                    if (throwing) throw new Win32Exception(Marshal.GetLastWin32Error());
                } else { plans = IntPtr.Zero; planCapacity = 0; }
            }
            if (buffer != IntPtr.Zero && !VirtualFree(buffer, 0, FreeType.Release)) {
                if (throwing) throw new Win32Exception(Marshal.GetLastWin32Error());
                return;
            }
            buffer = IntPtr.Zero;
            capacity = 0;
            disposed = true;
        }

        public void Dispose() { Release(true); GC.SuppressFinalize(this); }
        ~ThreadContextBuffer() { Release(false); }
    }
}
