using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using MinHook;
using Xunit;
using static MinHook.Utils;

namespace MinHook.Tests {
    public class ThreadContextTests {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateThread(IntPtr attributes, UIntPtr stackSize, IntPtr start, IntPtr parameter, uint flags, out uint id);
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        delegate int ReturnValue();

        sealed unsafe class NativeWorker : IDisposable {
            internal readonly IntPtr Page;
            internal readonly IntPtr Target;
            internal readonly IntPtr Control;
            internal readonly IntPtr Thread;
            bool parked;
            readonly ThreadContextBuffer contexts = new ThreadContextBuffer();

            internal NativeWorker(bool callHeader = false, bool conditionalHeader = false, bool hotpatch = false) {
                Page = VirtualAlloc(IntPtr.Zero, (IntPtr)4096, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
                Assert.NotEqual(IntPtr.Zero, Page);
                new Span<byte>((void*)Page, 4096).Fill(0xCC);
                Target = Page + 256;
                Control = Page + 3072;
                new Span<byte>((void*)Control, 16).Clear();
                // cmp [ecx/rcx],0; je back to cmp; xor eax,eax; ret.
                byte[] loop = { 0x83, 0x39, 0, 0x74, 0xFB, 0x31, 0xC0, 0xC3 };
                IntPtr body = conditionalHeader || hotpatch ? Target + 128 : callHeader ? Target + Trampoline.RelativeJumpSize : Target;
                Marshal.Copy(loop, 0, body, loop.Length);
                if (callHeader) {
                    Marshal.WriteByte(Target, 0xE8);
                    Marshal.WriteInt32(Target, 1, 512 - 5);
                    // inc dword ptr [ecx/rcx+8]; ret.
                    byte[] helper = { 0xFF, 0x41, 8, 0xC3 };
                    Marshal.Copy(helper, 0, Target + 512, helper.Length);
                }
                if (conditionalHeader) {
                    Marshal.WriteByte(Target, 0x0F);
                    Marshal.WriteByte(Target, 1, 0x84);
                    Marshal.WriteInt32(Target, 2, 128 - Trampoline.RelativeConditionalJumpSize);
                }
                if (hotpatch) {
                    new Span<byte>((void*)(Target - Trampoline.RelativeJumpSize), Trampoline.RelativeJumpSize).Fill(0x90);
                    Marshal.WriteByte(Target, 0xC3);
                    Marshal.WriteByte(Target, 1, 0x90);
                }
                int position = 0;
                if (IntPtr.Size == 4) {
                    byte[] parameter = { 0x8B, 0x4C, 0x24, 4 };
                    Marshal.Copy(parameter, 0, Page, parameter.Length);
                    position += parameter.Length;
                }
                // Notify managed code that the real OS thread entered its native start routine.
                byte[] ready = { 0xC7, 0x41, 4, 1, 0, 0, 0 };
                Marshal.Copy(ready, 0, Page + position, ready.Length);
                position += ready.Length;
                if (conditionalHeader) {
                    byte[] compare = { 0x83, 0x39, 0 };
                    Marshal.Copy(compare, 0, Page + position, compare.Length);
                    position += compare.Length;
                }
                Marshal.WriteByte(Page, position, IntPtr.Size == 4 ? (byte)0xE8 : (byte)0xE9);
                IntPtr entryTarget = hotpatch ? body : Target;
                Marshal.WriteInt32(Page, position + 1, checked((int)((long)entryTarget - ((long)Page + position + 5))));
                if (IntPtr.Size == 4) {
                    Marshal.WriteByte(Page, position + 5, 0xC2);
                    Marshal.WriteInt16(Page, position + 6, 4);
                }
                Assert.True(FlushInstructionCache((IntPtr)(-1), Page, (UIntPtr)4096));
                contexts.Prepare(1);
                Thread = CreateThread(IntPtr.Zero, UIntPtr.Zero, Page, Control, 0, out _);
                Assert.NotEqual(IntPtr.Zero, Thread);
                Assert.True(SpinWait.SpinUntil(() => Marshal.ReadInt32(Control, 4) != 0, 5000));
                Assert.True(SpinWait.SpinUntil(() => {
                    ulong ip = Inspect();
                    return ip == NativeMemory.Address(body) || ip == NativeMemory.Address(body + 3);
                }, 5000));
            }

            internal IntPtr Context => contexts.ContextAt(0);

            internal void Park(ulong ip) {
                if (!parked) { Assert.NotEqual(-1, SuspendThread(Thread)); parked = true; }
                ThreadContextBuffer.Initialize(Context);
                Assert.True(GetThreadContext(Thread, Context));
                ThreadContextBuffer.WriteIp(Context, ip);
                Assert.True(SetThreadContext(Thread, Context));
                // Windows sanitizes reserved flag bits; compare against the actual post-set context.
                ThreadContextBuffer.Initialize(Context);
                Assert.True(GetThreadContext(Thread, Context));
            }

            internal ulong Inspect() {
                bool temporary = !parked;
                if (temporary) Assert.NotEqual(-1, SuspendThread(Thread));
                try {
                    ThreadContextBuffer.Initialize(Context);
                    Assert.True(GetThreadContext(Thread, Context));
                    return ThreadContextBuffer.ReadIp(Context);
                } finally { if (temporary) Assert.NotEqual(uint.MaxValue, ResumeThread(Thread)); }
            }

            internal ulong StackPointer => IntPtr.Size == 8
                ? NativeMemory.AsRef<ThreadContextBuffer.Context64>(Context).Rsp
                : NativeMemory.AsRef<ThreadContextBuffer.Context32>(Context).Esp;

            internal uint Flags => IntPtr.Size == 8
                ? NativeMemory.AsRef<ThreadContextBuffer.Context64>(Context).EFlags
                : NativeMemory.AsRef<ThreadContextBuffer.Context32>(Context).EFlags;

            internal void Continue() {
                if (!parked) return;
                Assert.NotEqual(uint.MaxValue, ResumeThread(Thread));
                parked = false;
            }

            public void Dispose() {
                Marshal.WriteInt32(Control, 1);
                Continue();
                // Do not free executable memory while the native thread can still use it.
                if (WaitForSingleObject(Thread, 5000) != 0) throw new TimeoutException("Native worker did not exit.");
                Assert.True(CloseHandle(Thread));
                contexts.Dispose();
                Assert.True(VirtualFree(Page, 0, FreeType.Release));
            }
        }

        [Fact]
        public unsafe void ContextLayoutsMatchTheWindowsSdk() {
            Assert.Equal(716, sizeof(ThreadContextBuffer.Context32));
            Assert.Equal(1232, sizeof(ThreadContextBuffer.Context64));
            Assert.Equal(IntPtr.Size == 8 ? 200 : 184, sizeof(NativeHookPlan));
            Assert.Equal(32, sizeof(NativeThreadResult));
            Assert.Equal(184, Marshal.OffsetOf<ThreadContextBuffer.Context32>("Eip").ToInt32());
            Assert.Equal(248, Marshal.OffsetOf<ThreadContextBuffer.Context64>("Rip").ToInt32());
            using var buffer = new ThreadContextBuffer();
            buffer.Prepare(3);
            for (int i = 0; i < 3; i++) Assert.Equal(0UL, NativeMemory.Address(buffer.ContextAt(i)) % 16);
        }

        [Fact]
        public async Task NativeWorkerMigrationRunsInIsolatedProcess() {
            const string marker = "MINHOOK_NATIVE_CONTEXT_CHILD";
            if (Environment.GetEnvironmentVariable(marker) == "1") {
                Console.WriteLine("native: enable/disable/dispose");
                EnableDisableAndDispose();
                DisposeDisabledOriginal();
                HotpatchEntry();
                if (IntPtr.Size == 8) { ExpandedCallContinuation(); RelayEntry(); ExpandedConditionalBranch(); }
                Console.WriteLine("native: rollback failure paths");
                FailedContextUpdateRollsBack();
                FailedCaptureDoesNotChangeAnyThread();
                FailedPatchRollsBackInstructionPointers();
                UnknownBoundaryAbortsWithoutPatching();
                FailedSuspensionResumesEarlierThreads();
                CurrentThreadIsRejectedBeforeSuspension();
                ExitedThreadDoesNotAbortTransaction();
                ContextUpdatesDoNotAllocateAfterWarmup();
                Console.WriteLine("native: concurrent toggling");
                ConcurrentToggling();
                Console.WriteLine("native: concurrent collection");
                ConcurrentCollection();
                return;
            }
            var start = new ProcessStartInfo(Environment.ProcessPath) {
                UseShellExecute = false, CreateNoWindow = true,
                RedirectStandardOutput = true, RedirectStandardError = true
            };
            if (string.Equals(System.IO.Path.GetFileNameWithoutExtension(Environment.ProcessPath), "dotnet", StringComparison.OrdinalIgnoreCase))
                start.ArgumentList.Add(typeof(ThreadContextTests).Assembly.Location);
            else Assert.Equal(typeof(ThreadContextTests).Assembly.GetName().Name, System.IO.Path.GetFileNameWithoutExtension(Environment.ProcessPath));
            start.ArgumentList.Add("-noLogo");
            start.ArgumentList.Add("-method");
            start.ArgumentList.Add("*.NativeWorkerMigrationRunsInIsolatedProcess");
            start.Environment[marker] = "1";
            using var process = Process.Start(start);
            var stdout = process.StandardOutput.ReadToEndAsync(TestContext.Current.CancellationToken);
            var stderr = process.StandardError.ReadToEndAsync(TestContext.Current.CancellationToken);
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(TestContext.Current.CancellationToken);
            deadline.CancelAfter(30000);
            try { await process.WaitForExitAsync(deadline.Token); }
            catch (OperationCanceledException) {
                process.Kill(true);
                await process.WaitForExitAsync(TestContext.Current.CancellationToken);
                Assert.Fail("Native context probe exceeded its 30-second process deadline.\n" + await stdout + await stderr);
            }
            Assert.True(process.ExitCode == 0, await stdout + await stderr);
        }

        static void EnableDisableAndDispose() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            ReturnValue detour = () => 99;
            ReturnValue original = engine.CreateHook(worker.Target, detour);
            IntPtr trampoline = Marshal.GetFunctionPointerForDelegate(original);
            worker.Park(NativeMemory.Address(worker.Target + 3));
            ulong sp = worker.StackPointer;
            uint flags = worker.Flags;
            engine.EnableHook(original);
            Assert.Equal(NativeMemory.Address(trampoline + 3), worker.Inspect());
            Assert.Equal(sp, worker.StackPointer);
            Assert.Equal(flags, worker.Flags);
            worker.Continue();
            Thread.Sleep(10);
            worker.Park(NativeMemory.Address(trampoline + 3));
            engine.DisableHook(original);
            Assert.Equal(NativeMemory.Address(worker.Target + 3), worker.Inspect());
            Assert.Equal(sp, worker.StackPointer);
            engine.Dispose();
            worker.Continue();
        }

        static void DisposeDisabledOriginal() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            IntPtr trampoline = Marshal.GetFunctionPointerForDelegate(original);
            worker.Park(NativeMemory.Address(trampoline + 3));
            engine.Dispose();
            Assert.Equal(NativeMemory.Address(worker.Target + 3), worker.Inspect());
            MEMORY_BASIC_INFORMATION info = default;
            Assert.NotEqual(0, VirtualQuery(trampoline, ref info, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()));
            Assert.Equal(MemoryState.Free, info.State);
        }

        static void ExpandedCallContinuation() {
            using var worker = new NativeWorker(callHeader: true);
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            IntPtr trampoline = Marshal.GetFunctionPointerForDelegate(original);
            engine.EnableHook(original);
            worker.Park(NativeMemory.Address(trampoline + Trampoline.IndirectBranchInstructionSize));
            engine.DisableHook(original);
            Assert.Equal(NativeMemory.Address(worker.Target + Trampoline.RelativeJumpSize), worker.Inspect());
            worker.Continue();
            Thread.Sleep(10);
            Assert.Equal(1, Marshal.ReadInt32(worker.Control, 8));
        }

        static void RelayEntry() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            IntPtr trampoline = Marshal.GetFunctionPointerForDelegate(original);
            engine.EnableHook(original);
            worker.Park(NativeMemory.Address(trampoline + Trampoline.RelativeJumpSize + Trampoline.AbsoluteJumpSize));
            engine.DisableHook(original);
            Assert.Equal(NativeMemory.Address(worker.Target), worker.Inspect());
        }

        static void HotpatchEntry() {
            using var worker = new NativeWorker(hotpatch: true);
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            engine.EnableHook(original);
            worker.Park(NativeMemory.Address(worker.Target - Trampoline.RelativeJumpSize));
            engine.DisableHook(original);
            Assert.Equal(NativeMemory.Address(worker.Target), worker.Inspect());
        }

        static void ExpandedConditionalBranch() {
            using var worker = new NativeWorker(conditionalHeader: true);
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            IntPtr trampoline = Marshal.GetFunctionPointerForDelegate(original);
            engine.EnableHook(original);
            worker.Park(NativeMemory.Address(trampoline + Trampoline.ShortJumpSize));
            // The conditional decision was already made; removal must not evaluate it again.
            NativeMemory.AsRef<ThreadContextBuffer.Context64>(worker.Context).EFlags &= ~0x40u;
            Assert.True(SetThreadContext(worker.Thread, worker.Context));
            engine.DisableHook(original);
            Assert.Equal(NativeMemory.Address(worker.Target + 128), worker.Inspect());
        }

        static void ConcurrentToggling() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            for (int i = 0; i < 64; i++) {
                engine.EnableHook(original);
                engine.DisableHook(original);
            }
            engine.Dispose();
        }

        static void ConcurrentCollection() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            using var ready = new ManualResetEventSlim();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            bool stop = false;
            var collector = new Thread(() => {
                ready.Set();
                while (!Volatile.Read(ref stop)) {
                    GC.Collect(0, GCCollectionMode.Forced, blocking: true, compacting: true);
                    Thread.Sleep(1);
                }
            }) { IsBackground = true };
            collector.Start();
            Assert.True(ready.Wait(5000));
            try {
                for (int i = 0; i < 64; i++) {
                    engine.EnableHook(original);
                    engine.DisableHook(original);
                }
                engine.Dispose();
            } finally {
                Volatile.Write(ref stop, true);
                Assert.True(collector.Join(5000), "Concurrent collector did not exit.");
            }
        }

        static void FailedSuspensionResumesEarlierThreads() {
            using var first = new NativeWorker();
            using var second = new NativeWorker();
            using var allocator = new MemoryAllocator();
            using var buffer = new ThreadContextBuffer();
            var hook = new Hook(first.Target, first.Page + 1024, allocator.AllocateBuffer(first.Target));
            IntPtr readOnly = OpenThread(ThreadAccess.QUERY_INFORMATION | ThreadAccess.GET_CONTEXT |
                ThreadAccess.SET_CONTEXT | ThreadAccess.SYNCHRONIZE, false, GetThreadId(second.Thread));
            Assert.NotEqual(IntPtr.Zero, readOnly);
            try {
                var threads = new List<IntPtr> { first.Thread, readOnly };
                buffer.Prepare(2);
                var result = buffer.Execute(threads, hook, true, null);
                Assert.Equal(NativeThreadStatus.SuspendFailed, result.Status);
                Assert.Equal(5, result.Error);
                Assert.Equal(0U, result.PatchWritten);
                Assert.Equal(0, result.ResumeError);
            } finally { Assert.True(CloseHandle(readOnly)); }
            // Worker disposal waits for real exit and would fail if either suspend count leaked.
        }

        static void CurrentThreadIsRejectedBeforeSuspension() {
            using var worker = new NativeWorker();
            using var allocator = new MemoryAllocator();
            using var buffer = new ThreadContextBuffer();
            var hook = new Hook(worker.Target, worker.Page + 1024, allocator.AllocateBuffer(worker.Target));
            var threads = new List<IntPtr> { (IntPtr)(-2) }; // GetCurrentThread pseudo handle.
            buffer.Prepare(1);
            var result = buffer.Execute(threads, hook, true, null);
            Assert.Equal(NativeThreadStatus.InvalidInput, result.Status);
            Assert.Equal(0U, result.PatchWritten);
        }

        static void ExitedThreadDoesNotAbortTransaction() {
            using var page = new NativeTests.CodePage();
            using var allocator = new MemoryAllocator();
            using var buffer = new ThreadContextBuffer();
            // Return zero using the native thread-start ABI on both architectures.
            byte[] exit = IntPtr.Size == 8 ? new byte[] { 0x31, 0xC0, 0xC3 }
                : new byte[] { 0x31, 0xC0, 0xC2, 4, 0 };
            Marshal.Copy(exit, 0, page.Address, exit.Length);
            Assert.True(FlushInstructionCache((IntPtr)(-1), page.Address, (UIntPtr)exit.Length));
            IntPtr thread = CreateThread(IntPtr.Zero, UIntPtr.Zero, page.Address, IntPtr.Zero, 0, out _);
            Assert.NotEqual(IntPtr.Zero, thread);
            try {
                Assert.Equal(0U, WaitForSingleObject(thread, 5000));
                // Separate target: mov eax,42; ret.
                IntPtr target = page.Address + 64;
                Marshal.WriteByte(target, 0xB8);
                Marshal.WriteInt32(target, 1, 42);
                Marshal.WriteByte(target, 5, 0xC3);
                var hook = new Hook(target, target, allocator.AllocateBuffer(target));
                buffer.Prepare(1);
                var result = buffer.Execute(new List<IntPtr> { thread }, hook, true, null);
                Assert.Equal(NativeThreadStatus.Success, result.Status);
                Assert.Equal(1U, result.PatchWritten);
                hook.RecordNativePatch(true);
                hook.Enable(false);
            } finally { Assert.True(CloseHandle(thread)); }
        }

        static void FailedContextUpdateRollsBack() {
            using var first = new NativeWorker();
            using var second = new NativeWorker();
            using var allocator = new MemoryAllocator();
            var hook = new Hook(first.Target, first.Page + 1024, allocator.AllocateBuffer(first.Target));
            // Both threads are intentionally parked at boundaries of the same generated target.
            first.Park(NativeMemory.Address(first.Target));
            second.Park(NativeMemory.Address(first.Target));
            uint secondId = GetThreadId(second.Thread);
            IntPtr readOnly = OpenThread(ThreadAccess.GET_CONTEXT | ThreadAccess.QUERY_INFORMATION, false, secondId);
            Assert.NotEqual(IntPtr.Zero, readOnly);
            try {
                using var buffer = new ThreadContextBuffer();
                var handles = new List<IntPtr> { first.Thread, readOnly };
                buffer.Prepare(handles.Count);
                Assert.Equal(ContextUpdateResult.Success, buffer.CaptureAndPlan(handles, hook, true, null, out _));
                Assert.Equal(ContextUpdateResult.ApplyFailed, buffer.Apply(handles, out int error, out _));
                Assert.Equal(5, error);
                Assert.Equal(NativeMemory.Address(first.Target), first.Inspect());
                Assert.False(hook.Enabled);
            } finally { Assert.True(CloseHandle(readOnly)); }
            // Restore the second worker to its own loop before the first code page is freed.
            second.Park(NativeMemory.Address(second.Target));
        }

        static void FailedCaptureDoesNotChangeAnyThread() {
            using var worker = new NativeWorker();
            using var allocator = new MemoryAllocator();
            var hook = new Hook(worker.Target, worker.Page + 1024, allocator.AllocateBuffer(worker.Target));
            worker.Park(NativeMemory.Address(worker.Target));
            IntPtr queryOnly = OpenThread(ThreadAccess.QUERY_INFORMATION, false, GetThreadId(worker.Thread));
            Assert.NotEqual(IntPtr.Zero, queryOnly);
            try {
                using var buffer = new ThreadContextBuffer();
                var threads = new List<IntPtr> { worker.Thread, queryOnly };
                buffer.Prepare(2);
                Assert.Equal(ContextUpdateResult.CaptureFailed, buffer.CaptureAndPlan(threads, hook, true, null, out int error));
                Assert.Equal(5, error);
                Assert.Equal(NativeMemory.Address(worker.Target), worker.Inspect());
            } finally { Assert.True(CloseHandle(queryOnly)); }
        }

        static void FailedPatchRollsBackInstructionPointers() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            using var allocator = new MemoryAllocator();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            IntPtr trampoline = Marshal.GetFunctionPointerForDelegate(original);
            engine.EnableHook(original);
            var newer = new Hook(worker.Target, worker.Page + 1024, allocator.AllocateBuffer(worker.Target));
            newer.Enable();
            worker.Park(NativeMemory.Address(trampoline + 3));
            try {
                Assert.Throws<InvalidOperationException>(() => engine.DisableHook(original));
                Assert.Equal(NativeMemory.Address(trampoline + 3), worker.Inspect());
            } finally { newer.Enable(false); }
            // Dispose the owning engine before releasing code pages owned by either fixture.
            engine.Dispose();
        }

        static void ContextUpdatesDoNotAllocateAfterWarmup() {
            // This measures prepared buffers and transactions, not hook creation or thread enumeration.
            using var worker = new NativeWorker();
            using var allocator = new MemoryAllocator();
            using var buffer = new ThreadContextBuffer();
            var hook = new Hook(worker.Target, worker.Page + 1024, allocator.AllocateBuffer(worker.Target));
            var handles = new List<IntPtr> { worker.Thread };
            buffer.Prepare(1);
            worker.Park(NativeMemory.Address(worker.Target));
            for (int i = 0; i < 32; i++) UpdateAndRestore(buffer, handles, hook);
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 1000; i++) UpdateAndRestore(buffer, handles, hook);
            Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
            for (int i = 0; i < 16; i++) ToggleNativeTransaction(buffer, handles, hook);
            before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 128; i++) ToggleNativeTransaction(buffer, handles, hook);
            Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
        }

        static void ToggleNativeTransaction(ThreadContextBuffer buffer, List<IntPtr> threads, Hook hook) {
            var enabled = buffer.Execute(threads, hook, true, null);
            if (enabled.PatchWritten != 0) hook.RecordNativePatch(true);
            if (enabled.Status != NativeThreadStatus.Success) throw ThreadContextBuffer.CreateException(enabled);
            var disabled = buffer.Execute(threads, hook, false, null);
            if (disabled.PatchWritten != 0) hook.RecordNativePatch(false);
            if (disabled.Status != NativeThreadStatus.Success) throw ThreadContextBuffer.CreateException(disabled);
        }

        static void UnknownBoundaryAbortsWithoutPatching() {
            using var worker = new NativeWorker();
            using var engine = new HookEngine();
            ReturnValue original = engine.CreateHook(worker.Target, (ReturnValue)(() => 99));
            worker.Park(NativeMemory.Address(worker.Target + 1));
            try {
                Assert.Throws<NotSupportedException>(() => engine.EnableHook(original));
                Assert.Equal(0x83, Marshal.ReadByte(worker.Target));
                Assert.Equal(NativeMemory.Address(worker.Target + 1), worker.Inspect());
            } finally { worker.Park(NativeMemory.Address(worker.Target)); }
        }

        [Fact]
        public void ContextBufferReusesStorageAndReleasesItsReservation() {
            using var buffer = new ThreadContextBuffer();
            buffer.Prepare(1);
            IntPtr first = buffer.ContextAt(0);
            buffer.Prepare(1);
            Assert.Equal(first, buffer.ContextAt(0));
            buffer.Prepare(32);
            IntPtr grown = buffer.ContextAt(31);
            Assert.Equal(0UL, NativeMemory.Address(grown) % ThreadContextBuffer.ContextAlignment);
            buffer.Dispose();
            MEMORY_BASIC_INFORMATION info = default;
            Assert.NotEqual(0, VirtualQuery(grown, ref info, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()));
            Assert.Equal(MemoryState.Free, info.State);
            Assert.Throws<ObjectDisposedException>(() => buffer.Prepare(1));
        }

        static void UpdateAndRestore(ThreadContextBuffer buffer, List<IntPtr> threads, Hook hook) {
            if (buffer.CaptureAndPlan(threads, hook, true, null, out _) != ContextUpdateResult.Success ||
                buffer.Apply(threads, out _, out _) != ContextUpdateResult.Success || buffer.Rollback(threads) != 0)
                throw new InvalidOperationException("Native context cycle failed.");
        }

        [Fact]
        public unsafe void InstructionBoundariesAreMappedWithoutRounding() {
            using var page = new NativeTests.CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 32;
            // mov eax,42 occupies the complete five-byte patch region.
            Marshal.WriteByte(target, 0xB8);
            Marshal.WriteInt32(target, 1, 42);
            Marshal.WriteByte(target, 5, 0xC3);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            Assert.True(trampoline.TryMapInstructionPointer(NativeMemory.Address(target), true, false, out ulong mapped));
            Assert.Equal(NativeMemory.Address(trampoline.Tramp), mapped);
            Assert.True(trampoline.TryMapInstructionPointer(mapped, false, true, out ulong restored));
            Assert.Equal(NativeMemory.Address(target), restored);
            Assert.False(trampoline.TryMapInstructionPointer(NativeMemory.Address(target + 1), true, false, out _));
            Assert.False(trampoline.TryMapInstructionPointer(NativeMemory.Address(trampoline.Tramp + 1), false, true, out _));
            Assert.True(trampoline.TryMapInstructionPointer(NativeMemory.Address(page.Address + 512), false, true, out ulong unchanged));
            Assert.Equal(NativeMemory.Address(page.Address + 512), unchanged);
        }

        [Fact]
        public unsafe void HotpatchEntryMapsBackToTheOriginalTarget() {
            using var page = new NativeTests.CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 32;
            new Span<byte>((void*)(target - Trampoline.RelativeJumpSize), Trampoline.RelativeJumpSize).Fill(0x90);
            Marshal.WriteByte(target, 0xC3);
            Marshal.WriteByte(target, 1, 0x90);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            Assert.True(trampoline.PatchAbove);
            Assert.True(trampoline.TryMapInstructionPointer(NativeMemory.Address(target - Trampoline.RelativeJumpSize), false, true, out ulong mapped));
            Assert.Equal(NativeMemory.Address(target), mapped);
            Assert.False(trampoline.TryMapInstructionPointer(NativeMemory.Address(target - 1), false, true, out _));
        }

        public static bool Is64Bit => IntPtr.Size == 8;

        [Fact(SkipUnless = nameof(Is64Bit), Skip = "Expanded absolute Jcc instructions exist only on x64.")]
        public void TakenExpandedConditionalBranchKeepsItsDestination() {
            using var page = new NativeTests.CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 32;
            Marshal.WriteByte(target, 0x0F);
            Marshal.WriteByte(target, 1, 0x85);
            Marshal.WriteInt32(target, 2, 256 - 6);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            Assert.True(trampoline.TryMapInstructionPointer(NativeMemory.Address(trampoline.Tramp + Trampoline.ShortJumpSize), false, true, out ulong mapped));
            Assert.Equal(NativeMemory.Address(target + 256), mapped);
            Assert.False(trampoline.TryMapInstructionPointer(NativeMemory.Address(trampoline.Tramp + 8), false, true, out _));
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern uint GetThreadId(IntPtr thread);
    }
}
