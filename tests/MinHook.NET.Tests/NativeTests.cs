using System;
using System.Runtime.InteropServices;
using Xunit;
using static MinHook.Utils;

[assembly: CollectionBehavior(DisableTestParallelization = true)]

namespace MinHook.Tests {
    public unsafe class NativeTests {
        public static bool Is64Bit => IntPtr.Size == 8;
        internal sealed class CodePage : IDisposable {
            public readonly IntPtr Address = VirtualAlloc(IntPtr.Zero, (IntPtr)4096,
                AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

            public CodePage() {
                Assert.NotEqual(IntPtr.Zero, Address);
                new Span<byte>((void*)Address, 4096).Fill(0xCC);
            }

            public void Dispose() => Assert.True(VirtualFree(Address, 0, FreeType.Release));
        }

        [Theory]
        [InlineData(0x200)]
        [InlineData(-0x200)]
        public void Rel32JumpPreservesDestination(int displacement) {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 1024;
            Marshal.WriteByte(target, 0xE9);
            Marshal.WriteInt32(target, 1, displacement - 5);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            IntPtr destination = IntPtr.Size == 4
                ? trampoline.Tramp + 5 + Marshal.ReadInt32(trampoline.Tramp, 1)
                : (IntPtr)Marshal.ReadInt64(trampoline.Tramp, 6);
            Assert.Equal(target + displacement, destination);
        }

        [Fact]
        public void DisableUpdatesStateAndRestoresBytes() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            new Span<byte>((void*)(page.Address + 16), 16).Fill(0x90);
            var hook = new Hook(page.Address + 16, page.Address + 128, allocator.AllocateBuffer(page.Address));
            hook.Enable();
            hook.Enable(false);
            Assert.False(hook.Enabled);
            Assert.Equal(0x90, Marshal.ReadByte(page.Address, 16));
        }

        [Fact]
        public void ReleasingBlockActuallyReleasesReservation() {
            IntPtr address = VirtualAlloc(IntPtr.Zero, (IntPtr)4096,
                AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
            var block = new MemoryBlock(address);
            block.Dispose();
            MEMORY_BASIC_INFORMATION info = default;
            Assert.NotEqual(0, VirtualQuery(address, ref info, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>()));
            try { Assert.Equal(MemoryState.Free, info.State); }
            finally { if (info.State != MemoryState.Free) VirtualFree(address, 0, FreeType.Release); }
        }

        [Fact]
        public void DisposingAllocatorDoesNotInvalidateAnotherAllocator() {
            using var page = new CodePage();
            using var first = new MemoryAllocator();
            using var second = new MemoryAllocator();
            first.AllocateBuffer(page.Address);
            MemorySlot slot = second.AllocateBuffer(page.Address);
            first.Dispose();
            MemorySlot next = second.AllocateBuffer(page.Address);
            Assert.Equal(slot.Address + 64, next.Address);
        }

        [Fact]
        public void PaddingAfterShortFunctionDoesNotRequirePatchAbove() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            Marshal.WriteByte(target, 0xC3);
            new Span<byte>((void*)(target + 1), 4).Fill(0x90);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            Assert.False(trampoline.PatchAbove);
        }

        [Fact]
        public void ShortFunctionCannotOverwriteNonPaddingBytes() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            new Span<byte>((void*)(target - 5), 10).Fill(0x01);
            Marshal.WriteByte(target, 0xC3);
            Assert.ThrowsAny<Exception>(() => new Trampoline(target, target, allocator.AllocateBuffer(target)));
        }

        [Theory]
        [InlineData(0x7F)]
        [InlineData(-0x40)]
        public void ShortJumpPreservesSignedDestination(int displacement) {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 1024;
            Marshal.WriteByte(target, 0xEB);
            Marshal.WriteByte(target, 1, unchecked((byte)(displacement - 2)));
            new Span<byte>((void*)(target + 2), 3).Fill(0x90);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            IntPtr destination = IntPtr.Size == 4
                ? trampoline.Tramp + 5 + Marshal.ReadInt32(trampoline.Tramp, 1)
                : (IntPtr)Marshal.ReadInt64(trampoline.Tramp, 6);
            Assert.Equal(target + displacement, destination);
        }

        [Theory]
        [InlineData(false, false)]
        [InlineData(false, true)]
        [InlineData(true, false)]
        [InlineData(true, true)]
        public void ConditionalJumpPreservesConditionAndDestination(bool near, bool backward) {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 1024;
            int offset = backward ? -64 : 64;
            if (near) {
                Marshal.WriteByte(target, 0x0F);
                Marshal.WriteByte(target, 1, 0x85);
                Marshal.WriteInt32(target, 2, offset - 6);
            } else {
                Marshal.WriteByte(target, 0x75);
                Marshal.WriteByte(target, 1, unchecked((byte)(offset - 2)));
                new Span<byte>((void*)(target + 2), 4).Fill(0x90);
            }
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            if (IntPtr.Size == 4) {
                Assert.Equal(0x0F, Marshal.ReadByte(trampoline.Tramp));
                Assert.Equal(0x85, Marshal.ReadByte(trampoline.Tramp, 1));
                Assert.Equal(target + offset, trampoline.Tramp + 6 + Marshal.ReadInt32(trampoline.Tramp, 2));
            } else {
                Assert.Equal(0x74, Marshal.ReadByte(trampoline.Tramp));
                Assert.Equal(target + offset, (IntPtr)Marshal.ReadInt64(trampoline.Tramp, 8));
            }
        }

        [Fact]
        public void HotpatchRestoresAllSevenBytes() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            new Span<byte>((void*)(target - 5), 5).Fill(0x90);
            Marshal.WriteByte(target, 0xC3);
            Marshal.WriteByte(target, 1, 0x90);
            byte[] before = new ReadOnlySpan<byte>((void*)(target - 5), 7).ToArray();
            var hook = new Hook(target, page.Address + 128, allocator.AllocateBuffer(target));
            hook.Enable();
            Assert.Equal(0xE9, Marshal.ReadByte(target, -5));
            Assert.Equal(0xEB, Marshal.ReadByte(target));
            hook.Enable(false);
            Assert.True(new ReadOnlySpan<byte>((void*)(target - 5), 7).SequenceEqual(before));
        }

        [Fact]
        public void PatchAndRestoreDoNotAllocateAfterWarmup() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            new Span<byte>((void*)(page.Address + 16), 16).Fill(0x90);
            var hook = new Hook(page.Address + 16, page.Address + 128, allocator.AllocateBuffer(page.Address));
            for (int i = 0; i < 100; i++) { hook.Enable(); hook.Enable(false); }
            long before = GC.GetAllocatedBytesForCurrentThread();
            for (int i = 0; i < 1000; i++) { hook.Enable(); hook.Enable(false); }
            Assert.Equal(0, GC.GetAllocatedBytesForCurrentThread() - before);
        }

        [Theory(SkipUnless = nameof(Is64Bit), Skip = "RIP-relative addressing requires an x64 process.")]
        [InlineData(false)]
        [InlineData(true)]
        public void RipRelativeDisplacementDoesNotOverwriteImmediate(bool immediate) {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            // mov eax,[rip+disp32] or mov dword ptr [rip+disp32],imm32.
            Marshal.WriteByte(target, immediate ? (byte)0xC7 : (byte)0x8B);
            Marshal.WriteByte(target, 1, 0x05);
            Marshal.WriteInt32(target, 2, 128);
            if (immediate) Marshal.WriteInt32(target, 6, 0x12345678);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            int length = immediate ? 10 : 6;
            Assert.Equal(target + length + 128, trampoline.Tramp + length + Marshal.ReadInt32(trampoline.Tramp, 2));
            if (immediate) Assert.Equal(0x12345678, Marshal.ReadInt32(trampoline.Tramp, 6));
        }

        [Fact]
        public void IndirectCallIsCopiedWithoutRelocation() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            // call eax/rax is register-indirect, not a relative call.
            Marshal.WriteByte(target, 0xFF);
            Marshal.WriteByte(target, 1, 0xD0);
            new Span<byte>((void*)(target + 2), 4).Fill(0x90);
            var trampoline = new Trampoline(target, target, allocator.AllocateBuffer(target));
            Assert.Equal(0xFF, Marshal.ReadByte(trampoline.Tramp));
            Assert.Equal(0xD0, Marshal.ReadByte(trampoline.Tramp, 1));
        }

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int ReturnValue();

        [Fact]
        public void OriginalRemainsCallableAcrossEnableDisableCycles() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            new Span<byte>((void*)target, 5).Fill(0x90);
            // mov eax,42; ret
            Marshal.WriteByte(target, 5, 0xB8);
            Marshal.WriteInt32(target, 6, 42);
            Marshal.WriteByte(target, 10, 0xC3);
            ReturnValue original = null;
            ReturnValue detour = () => original() + 1;
            var hook = new Hook(target, Marshal.GetFunctionPointerForDelegate(detour), allocator.AllocateBuffer(target));
            original = Marshal.GetDelegateForFunctionPointer<ReturnValue>(hook.Original);
            ReturnValue invoke = Marshal.GetDelegateForFunctionPointer<ReturnValue>(target);
            for (int i = 0; i < 100; i++) {
                hook.Enable();
                Assert.Equal(43, invoke());
                Assert.Equal(42, original());
                hook.Enable(false);
                Assert.Equal(42, invoke());
            }
            GC.KeepAlive(detour);
        }

        [Fact]
        public void OlderHookCannotEraseNewerHook() {
            using var page = new CodePage();
            using var allocator = new MemoryAllocator();
            IntPtr target = page.Address + 16;
            new Span<byte>((void*)target, 16).Fill(0x90);
            var older = new Hook(target, page.Address + 128, allocator.AllocateBuffer(target));
            older.Enable();
            var newer = new Hook(target, page.Address + 256, allocator.AllocateBuffer(target));
            newer.Enable();
            byte[] patch = new ReadOnlySpan<byte>((void*)target, Trampoline.RelativeJumpSize).ToArray();
            try {
                Assert.Throws<InvalidOperationException>(() => older.Enable(false));
                Assert.True(older.Enabled);
                Assert.True(new ReadOnlySpan<byte>((void*)target, patch.Length).SequenceEqual(patch));
            } finally {
                newer.Enable(false);
                older.Enable(false);
            }
        }

        [Fact]
        public void EngineDisposesLayersInReverseOrder() {
            using var page = new CodePage();
            using var engine = new HookEngine();
            IntPtr target = page.Address + 16;
            new Span<byte>((void*)target, 16).Fill(0x90);
            ReturnValue first = () => 1;
            ReturnValue second = () => 2;
            ReturnValue original = engine.CreateHook(target, first);
            engine.EnableHook(original);
            ReturnValue next = engine.CreateHook(target, second);
            engine.EnableHook(next);
            engine.Dispose();
            Assert.Equal(0x90, Marshal.ReadByte(target));
            engine.Dispose();
            Assert.Throws<ObjectDisposedException>(() => engine.EnableHook(original));
        }

        [Fact]
        public void FailedCreationReturnsTheMemorySlot() {
            using var page = new CodePage();
            using var engine = new HookEngine();
            IntPtr target = page.Address + 16;
            new Span<byte>((void*)(target - Trampoline.RelativeJumpSize), 16).Fill(0x01);
            Marshal.WriteByte(target, 0xC3);
            ReturnValue detour = () => 1;
            for (int i = 0; i < 128; i++) {
                Assert.ThrowsAny<Exception>(() => engine.CreateHook(target, detour));
            }
            var field = typeof(HookEngine).GetField("memoryAllocator", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
            var allocator = (MemoryAllocator)field.GetValue(engine);
            Assert.Equal(0, allocator.AllocateBuffer(target).Index);
        }

        [Fact(SkipUnless = nameof(Is64Bit), Skip = "Nearby allocation is used only by the x64 allocator.")]
        public void NearbySearchStartsOnTheRequestedSide() {
            const uint granularity = 0x10000;
            IntPtr window = VirtualAlloc(IntPtr.Zero, (IntPtr)(3 * granularity), AllocationType.Reserve, MemoryProtection.NoAccess);
            Assert.NotEqual(IntPtr.Zero, window);
            Assert.True(VirtualFree(window, 0, FreeType.Release));
            IntPtr middle = VirtualAlloc(window + (int)granularity, (IntPtr)granularity, AllocationType.Reserve, MemoryProtection.NoAccess);
            Assert.Equal(window + (int)granularity, middle);
            try {
                using var allocator = new MemoryAllocator();
                Assert.Equal(window, allocator.FindPrevFreeRegion(middle, window, granularity));
                Assert.Equal(window + 2 * (int)granularity, allocator.FindNextFreeRegion(middle, window + 2 * (int)granularity, granularity));
            } finally { Assert.True(VirtualFree(middle, 0, FreeType.Release)); }
        }
    }
}
