using System;
using System.Runtime.InteropServices;

namespace MinHook {
    internal static unsafe class NativeMemory {
        internal static ref T AsRef<T>(IntPtr address) where T : unmanaged {
#if NETFRAMEWORK
            return ref *(T*)address;
#else
            return ref MemoryMarshal.GetReference(MemoryMarshal.Cast<byte, T>(new Span<byte>((void*)address, sizeof(T))));
#endif
        }

        internal static ulong Address(IntPtr value) {
            return IntPtr.Size == 8 ? unchecked((ulong)value.ToInt64()) : unchecked((uint)value.ToInt32());
        }

        internal static void Write<T>(IntPtr destination, ref T value) where T : unmanaged {
#if NETFRAMEWORK
            fixed (T* valuePointer = &value) {
                byte* source = (byte*)valuePointer;
                byte* target = (byte*)destination;
                for (int i = 0; i < sizeof(T); i++) target[i] = source[i];
            }
#else
            MemoryMarshal.Cast<byte, T>(new Span<byte>((void*)destination, sizeof(T)))[0] = value;
#endif
        }

        internal static void Copy(IntPtr destination, IntPtr source, int count) {
#if NETFRAMEWORK
            byte* target = (byte*)destination;
            byte* input = (byte*)source;
            // The source and destination must be distinct buffers.
            for (int i = 0; i < count; i++) target[i] = input[i];
#else
            new ReadOnlySpan<byte>((void*)source, count).CopyTo(new Span<byte>((void*)destination, count));
#endif
        }

        internal static void Restore(IntPtr destination, byte[] backup, int count) {
            fixed (byte* source = backup) Copy(destination, (IntPtr)source, count);
        }

        internal static bool Equals<T>(IntPtr address, ref T value) where T : unmanaged {
#if NETFRAMEWORK
            fixed (T* expected = &value) {
                byte* actual = (byte*)address;
                byte* source = (byte*)expected;
                for (int i = 0; i < sizeof(T); i++) if (actual[i] != source[i]) return false;
                return true;
            }
#else
            ReadOnlySpan<byte> expected = MemoryMarshal.AsBytes(MemoryMarshal.CreateReadOnlySpan(ref value, 1));
            return new ReadOnlySpan<byte>((void*)address, sizeof(T)).SequenceEqual(expected);
#endif
        }

        internal static bool Equals(IntPtr address, byte[] expected, int count) {
#if NETFRAMEWORK
            byte* actual = (byte*)address;
            for (int i = 0; i < count; i++) if (actual[i] != expected[i]) return false;
            return true;
#else
            return new ReadOnlySpan<byte>((void*)address, count).SequenceEqual(expected.AsSpan(0, count));
#endif
        }
    }
}
