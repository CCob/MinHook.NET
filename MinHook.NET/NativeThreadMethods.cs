using System;
using System.Runtime.InteropServices;

namespace MinHook {
    internal enum NativeThreadStatus {
        Success, CaptureFailed, UnmappedInstruction, ApplyFailed, SuspendFailed,
        ResumeFailed, PatchChanged, ProtectionChangeFailed, ProtectionRestoreFailed, CacheFlushFailed, InvalidInput
    }

    [StructLayout(LayoutKind.Sequential)]
    internal unsafe struct NativeHookPlan {
        internal IntPtr Target, Trampoline, Relay, Destination;
        internal ulong AbsoluteCalls, AbsoluteConditionalJumps;
        internal uint BoundaryCount, PatchAbove, Enabled;
        internal fixed byte OldIps[64];
        internal fixed byte NewIps[64];
        internal fixed byte Backup[8];
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NativeThreadResult {
        internal NativeThreadStatus Status;
        internal int Error, RollbackError, ResumeError;
        internal ulong FailedIp;
        internal uint PatchWritten;
    }

    internal static class NativeThreadMethods {
        // Ship this DLL with the managed assembly, using the process bitness, not the OS bitness.
        // Direct DLL references must copy it to build and publish output themselves.
        const string Library = "MinHook.Threads.dll";

        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int mh_map_ip(ref NativeHookPlan hook, ulong ip, int enable, out ulong mapped);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void mh_capture(IntPtr threads, uint count, IntPtr hooks, uint hookCount, int enable, out NativeThreadResult result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void mh_apply(IntPtr threads, uint count, out uint applied, out NativeThreadResult result);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern int mh_rollback(IntPtr threads, uint applied);
        [DllImport(Library, CallingConvention = CallingConvention.Cdecl, ExactSpelling = true)]
        internal static extern void mh_execute(IntPtr threads, uint count, IntPtr hooks, uint hookCount,
            int enable, int writePatch, out NativeThreadResult result);
    }
}
