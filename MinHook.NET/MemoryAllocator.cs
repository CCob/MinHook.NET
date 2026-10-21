using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    internal class MemorySlot {

        public IntPtr Address { get; private set; }
        public int Index { get; private set; }

        public MemorySlot(IntPtr address, int index) {
            Address = address;
            Index = index;
        }
    }

    internal class MemoryBlock : IDisposable {

        // Page size for Windows
        internal const int MemoryBlockSize = 0x1000;
        internal const int MemorySlotSize = 64;

        public IntPtr BaseAddress { get; private set; }
        ulong freeBitMap;

        public MemoryBlock(IntPtr baseAddress) {
            this.BaseAddress = baseAddress;
            freeBitMap = ulong.MaxValue;
        }

        ~MemoryBlock() {
            Dispose(false);
        }

        protected void Dispose(bool disposing) {
            if(BaseAddress != IntPtr.Zero) {                
                if (!VirtualFree(BaseAddress, 0, FreeType.Release)) {
                    if (disposing) throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                    return;
                }
                BaseAddress = IntPtr.Zero;
            }
        }
      
        public bool IsFull() {
            return freeBitMap == 0;
        }

        public MemorySlot AllocateSlot() {

            if (BaseAddress == IntPtr.Zero) throw new ObjectDisposedException(nameof(MemoryBlock));

            if (IsFull()) {
                throw new OutOfMemoryException("No free slots available");
            }
            
            for(int idx = 0; idx < 64; idx++) {
                if( ((freeBitMap >> idx) & 1) == 1) {
                    freeBitMap ^= (1ul << idx);
                    return new MemorySlot((IntPtr)((long)BaseAddress + (idx * MemorySlotSize)), idx);
                }
            }

            throw new InvalidOperationException("Unexpected memory block state");
        }

        public void FreeSlot(MemorySlot memorySlot) {

            if((ulong)memorySlot.Address < (ulong)BaseAddress || (ulong)memorySlot.Address >= (ulong)BaseAddress + MemoryBlockSize) {
                throw new ArgumentException("memorySlot does not belong to this block");
            }

            freeBitMap |= (1ul << memorySlot.Index);
        }

        public void Dispose() {
            Dispose(true);
            GC.SuppressFinalize(this);
        }      
    }

    internal sealed class MemoryAllocator : IDisposable {

        // Page size for Windows
        static uint MEMORY_BLOCK_SIZE = 0x1000;

        // Max range for seeking a memory block. (= 1024MB)
        static uint MAX_MEMORY_RANGE = 0x40000000;

        readonly List<MemoryBlock> memoryBlocks = new List<MemoryBlock>();
        bool disposed;

        public MemoryAllocator() {

        }

        public MemorySlot AllocateBuffer(IntPtr origin) {
            if (disposed) throw new ObjectDisposedException(nameof(MemoryAllocator));
            MemoryBlock block = GetMemoryBlock(origin);               
            return block.AllocateSlot();
        }

        internal void FreeBuffer(MemorySlot slot) {
            if (disposed) throw new ObjectDisposedException(nameof(MemoryAllocator));
            foreach (MemoryBlock block in memoryBlocks) {
                if ((ulong)slot.Address >= (ulong)block.BaseAddress &&
                    (ulong)slot.Address < (ulong)block.BaseAddress + MemoryBlock.MemoryBlockSize) {
                    block.FreeSlot(slot);
                    return;
                }
            }
            throw new ArgumentException("Slot does not belong to this allocator", nameof(slot));
        }

        MemoryBlock GetMemoryBlock(IntPtr origin) {

            IntPtr minAddr = IntPtr.Zero;
            IntPtr maxAddr = IntPtr.Zero;
            MemoryBlock result = null;
            SYSTEM_INFO si = new SYSTEM_INFO();
            GetSystemInfo(ref si);

            if (IntPtr.Size == 8) {

                minAddr = si.lpMinimumApplicationAddress;
                maxAddr = si.lpMaximumApplicationAddress;

                if ((ulong)origin > MAX_MEMORY_RANGE && (ulong)minAddr < (ulong)origin - MAX_MEMORY_RANGE)
                    minAddr = (IntPtr)((ulong)origin - MAX_MEMORY_RANGE);

                if ((ulong)maxAddr > (ulong)origin + MAX_MEMORY_RANGE)
                    maxAddr = (IntPtr)((ulong)origin + MAX_MEMORY_RANGE);

                maxAddr = (IntPtr)((ulong)maxAddr - MEMORY_BLOCK_SIZE - 1);
            }

            foreach(var memoryBlock in memoryBlocks) {

                if(IntPtr.Size == 8 && ((ulong)memoryBlock.BaseAddress < (ulong)minAddr || (ulong)memoryBlock.BaseAddress >= (ulong)maxAddr)) {
                    continue;                   
                }

                if (!memoryBlock.IsFull()) {
                    return memoryBlock;
                }
            }

            //Couldn't find a free block, lets allocate another

            if(IntPtr.Size == 8) {

                IntPtr alloc = origin;
                while((ulong)alloc >= (ulong)minAddr) {

                    alloc = FindPrevFreeRegion(alloc, minAddr, si.dwAllocationGranularity);

                    if(alloc == IntPtr.Zero) {
                        break;
                    }

                    IntPtr baseAddr = VirtualAlloc(alloc, (IntPtr)MEMORY_BLOCK_SIZE, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

                    if (baseAddr != IntPtr.Zero) {
                        result = new MemoryBlock(baseAddr);
                        break;
                    }
                }

                if(result == null) {

                    alloc = origin;
                    while((ulong)alloc <= (ulong)maxAddr) {
                        alloc = FindNextFreeRegion(alloc, maxAddr, si.dwAllocationGranularity);

                        if (alloc == IntPtr.Zero)
                            break;

                        IntPtr baseAddr = VirtualAlloc(alloc, (IntPtr)MEMORY_BLOCK_SIZE, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);

                        if (baseAddr != IntPtr.Zero) {
                            result = new MemoryBlock(baseAddr);
                            break;
                        }
                    }
                }
            } else {

                IntPtr baseAddr = VirtualAlloc(IntPtr.Zero, (IntPtr)MEMORY_BLOCK_SIZE, AllocationType.Commit | AllocationType.Reserve, MemoryProtection.ExecuteReadWrite);
                if(baseAddr == IntPtr.Zero) {
                    throw new OutOfMemoryException("Failed to allocate new block of memory");
                }

                result = new MemoryBlock(baseAddr);
            }

            if(result == null) {
                throw new OutOfMemoryException("Failed to allocate new block of memory");
            }
                
            memoryBlocks.Add(result);
            return result;
        }

        internal IntPtr FindPrevFreeRegion(IntPtr address, IntPtr minAddress, uint allocationGranularity) {

            ulong alignedAddress = (ulong)address - (ulong)address % allocationGranularity;
            if (alignedAddress < allocationGranularity) return IntPtr.Zero;
            IntPtr tryAddr = (IntPtr)(alignedAddress - allocationGranularity);
            
            while((ulong)tryAddr >= (ulong)minAddress) {

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                if (VirtualQuery(tryAddr, ref mbi, Marshal.SizeOf(mbi)) == 0)
                    break;
              
                if(mbi.State == MemoryState.Free) 
                    return tryAddr;

                if ((ulong)mbi.AllocationBase < allocationGranularity)
                    break;

                tryAddr = (IntPtr)((ulong)mbi.AllocationBase - allocationGranularity);
            }

            return IntPtr.Zero;
        }

        internal IntPtr FindNextFreeRegion(IntPtr address, IntPtr maxAddress, uint allocationGranularity) {

            ulong alignedAddress = (ulong)address - (ulong)address % allocationGranularity;
            if (alignedAddress > ulong.MaxValue - allocationGranularity) return IntPtr.Zero;
            IntPtr tryAddr = (IntPtr)(alignedAddress + allocationGranularity);

            while ((ulong)tryAddr <= (ulong)maxAddress) {

                MEMORY_BASIC_INFORMATION mbi = new MEMORY_BASIC_INFORMATION();

                if (VirtualQuery(tryAddr, ref mbi, Marshal.SizeOf(mbi)) == 0)
                    break;

                if (mbi.State == MemoryState.Free)
                    return tryAddr;

                if ((ulong)mbi.AllocationBase < allocationGranularity)
                    break;

                tryAddr = (IntPtr)((ulong)mbi.BaseAddress + (ulong)mbi.RegionSize);

                tryAddr = (IntPtr)((long)tryAddr + (allocationGranularity - 1));
                tryAddr = (IntPtr)((ulong)tryAddr - ((ulong)tryAddr % allocationGranularity));
            }

            return IntPtr.Zero;
        }

        public void Dispose() {
            if (disposed) return;
            foreach(var block in memoryBlocks) {
                block.Dispose();
            }
            memoryBlocks.Clear();
            disposed = true;
            GC.SuppressFinalize(this);
        }
    }
}
