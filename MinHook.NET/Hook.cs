using System;

namespace MinHook {
    internal sealed class Hook {
        public bool Enabled { get; private set; }
        public bool QueueEnabled { get; private set; }
        public IntPtr Original { get; private set; }
        internal IntPtr Target { get { return trampoline.Target; } }

        readonly Trampoline trampoline;

        public Hook(IntPtr target, IntPtr detour, MemorySlot memorySlot) {
            trampoline = new Trampoline(target, detour, memorySlot);
            Original = trampoline.Tramp;
        }

        // Internal low-level operation for already-quiescent callers. HookEngine enlists threads.
        public unsafe void Enable(bool enable = true) {
            if (Enabled == enable) return;
            NativeHookPlan plan = default;
            WriteNativePlan(ref plan);
            NativeThreadMethods.mh_execute(IntPtr.Zero, 0, (IntPtr)(&plan), 1, enable ? 1 : 0, 1, out var result);
            if (result.PatchWritten != 0) Enabled = enable;
            if (result.Status != NativeThreadStatus.Success) throw ThreadContextBuffer.CreateException(result);
        }

        internal void WriteNativePlan(ref NativeHookPlan plan) { trampoline.WriteNativePlan(ref plan, Enabled); }
        internal void RecordNativePatch(bool enabled) { Enabled = enabled; }
    }
}
