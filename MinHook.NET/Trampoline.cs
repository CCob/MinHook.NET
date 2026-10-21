using SharpDisasm;
using SharpDisasm.Udis86;
using System;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.InteropServices;
using static MinHook.Utils;

namespace MinHook {
    internal sealed unsafe class Trampoline{

        internal static readonly int RelativeJumpSize = sizeof(JMPCALL_REL);
        internal static readonly int ShortJumpSize = sizeof(JMP_REL_SHORT);
        internal static readonly int AbsoluteJumpSize = sizeof(JMP_ABS);
        internal static readonly int AbsoluteCallSize = sizeof(CALL_ABS);
        internal static readonly int RelativeConditionalJumpSize = sizeof(JCC_REL);
        internal static readonly int AbsoluteConditionalJumpSize = sizeof(JCC_ABS);

        public interface AddressSupport {
            void SetAddress(IntPtr address);
        }

        public interface OperandSupport {
            void SetOperand(uint operand);
        }

        public interface OpcodeSupport {
            void SetOpcode(byte opcode);
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct JMP_REL_SHORT {
            byte opcode;      // EB xx: JMP +2+xx
            byte operand;

            public JMP_REL_SHORT(byte opcode, byte operand) {
                this.opcode = opcode;
                this.operand = operand;
            }
        }

        // 32-bit direct relative jump/call.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct JMPCALL_REL : OperandSupport {
            byte opcode;             // E9/E8 xxxxxxxx: JMP/CALL +5+xxxxxxxx
            public uint operand;     // Relative destination address

            public JMPCALL_REL(byte opcode) {
                this.opcode = opcode;
                operand = 0;
            }
 
            public void SetOperand(uint operand) {
                this.operand = operand;
            }
        }

        // 64-bit indirect absolute jump.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct JMP_ABS : AddressSupport {
            byte opcode0;     // FF25 00000000: JMP [+6]
            byte opcode1;
            uint dummy;
            public ulong address;     // Absolute destination address

            public JMP_ABS(IntPtr addr) {
                opcode0 = 0xFF;
                opcode1 = 0x25;
                dummy = 0;
                address = (ulong)addr;
            }

            public void SetAddress(IntPtr address) {
                this.address = (ulong)address;
            }
        }

        // 64-bit indirect absolute call.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct CALL_ABS : AddressSupport {
            byte opcode0;     // FF15 00000002: CALL [+6]
            byte opcode1;
            uint dummy0;
            byte dummy1;      // EB 08:         JMP +10
            byte dummy2;
            public ulong address;    // Absolute destination address

            public CALL_ABS(IntPtr addr) {
                opcode0 = 0xFF;
                opcode1 = 0x15;
                dummy0 = 0x000000002;
                dummy1 = 0xEB;
                dummy2 = 0x08;
                address = (ulong)addr;
            }

            public void SetAddress(IntPtr address) {
                this.address = (ulong)address;
            }
        }

        // 32-bit direct relative conditional jumps.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct JCC_REL : OperandSupport, OpcodeSupport {
            byte opcode0;     // 0F8* xxxxxxxx: J** +6+xxxxxxxx
            byte opcode1;
            uint operand;     // Relative destination address

            public JCC_REL(uint operand) {
                opcode0 = 0x0F;
                opcode1 = 0x80;
                this.operand = operand;
            }

            public void SetOpcode(byte opcode) {
                this.opcode1 = opcode;
            }

            public void SetOperand(uint operand) {
                this.operand = operand;
            }
        }

        // 64bit indirect absolute conditional jumps that x64 lacks.
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        struct JCC_ABS : AddressSupport, OpcodeSupport {
            byte opcode;      // 7* 0E:         J** +16
            byte dummy0;
            byte dummy1;      // FF25 00000000: JMP [+6]
            byte dummy2;
            uint dummy3;
            public ulong address;    // Absolute destination address

            public JCC_ABS(IntPtr addr) {
                opcode = 0x70;
                dummy0 = 0x0E;
                dummy1 = 0xFF;
                dummy2 = 0x25;
                dummy3 = 0;
                address = (ulong)addr;
            }

            public void SetAddress(IntPtr address) {
                this.address = (ulong)address;
            }

            public void SetOpcode(byte opcode) {
                this.opcode = opcode;
            }
        }  
                
        public IntPtr Target { get; private set; }
        public IntPtr Detour { get; private set; }
        public IntPtr Tramp { get; private set; } 
        public IntPtr Relay { get; private set; }
        public bool PatchAbove { get; private set; }
        public uint InstructionBoundaries { get; private set; }
        public byte[] OldInstructionBoundaries { get; private set; } = new byte[64];
        public byte[] NewInstructionBoundaries { get; private set; } = new byte[64];
        public byte[] Backup { get; private set; } = new byte[8];
        ulong absoluteCalls;
        ulong absoluteConditionalJumps;

        internal const int IndirectBranchInstructionSize = sizeof(ushort) + sizeof(int);

        public readonly int TrampolineMaxSize = MemoryBlock.MemorySlotSize - (IntPtr.Size == 8 ? AbsoluteJumpSize : 0);

        static int PAGE_EXECUTE = 0x10;
        static int PAGE_EXECUTE_READ = 0x20;
        static int PAGE_EXECUTE_READWRITE = 0x40;
        static int PAGE_EXECUTE_WRITECOPY = 0x80;
        static int PAGE_EXECUTE_FLAGS = (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

        [SuppressMessage("CodeQuality", "IDE0052:Remove unread private members", Justification = "MemorySlot has unmanged resources that we need to hold onto to prevent GC")]
        readonly MemorySlot memorySlot;

        public unsafe Trampoline(IntPtr target, IntPtr detour, MemorySlot memorySlot ) {

            Target = target;
            Detour = detour;
            Tramp = memorySlot.Address;
            this.memorySlot = memorySlot;

            uint oldPos = 0;
            uint newPos = 0;
            IntPtr jmpDest = IntPtr.Zero;
            byte* instructionBuffer = stackalloc byte[16];
            IntPtr instBuf = (IntPtr)instructionBuffer;
            bool finished = false;
            bool is64 = IntPtr.Size == 8;

            do {
                uint copySize;
                IntPtr copySrc;
                IntPtr oldInst = (IntPtr)((long)Target + oldPos);
                IntPtr newInst = (IntPtr)((long)Tramp + newPos);
               
                Instruction inst;
                using (Disassembler disasm = new Disassembler(oldInst, 15, is64 ? ArchitectureMode.x86_64 : ArchitectureMode.x86_32)) {
                    inst = disasm.NextInstruction();
                }

                if (inst == null) throw new NotSupportedException("Unable to decode target instruction");
                if (inst.Error)
                    throw new Exception(inst.ErrorMessage);

                copySrc = oldInst;
                copySize = (uint)inst.Length;
                int opcodeOffset = 0;
                byte opcode = Marshal.ReadByte(oldInst);
                while (IsPrefix(opcode, is64) && opcodeOffset + 1 < inst.Length) {
                    opcode = Marshal.ReadByte(oldInst, ++opcodeOffset);
                }

                if(oldPos >= RelativeJumpSize) {

                    copySize = WriteJump(instBuf, newInst, oldInst, is64);
                    copySrc = instBuf;
                    finished = true;

                }else if (is64 && inst.adr_mode == 64 && inst.HasModRM && ((inst.ModRM & 0xC7) == 0x5)) {

                    byte modRMReg = (byte)((inst.ModRM & 0x3f) >> 3);                    
                    copySrc = instBuf;
                    NativeMemory.Copy(instBuf, oldInst, (int)copySize);
                    int displacementOffset = inst.ModRMOffset + 1;
                    int oldDisplacement = Marshal.ReadInt32(oldInst, displacementOffset);
                    int displacement = checked((int)((long)oldInst + inst.Length + oldDisplacement - ((long)newInst + inst.Length)));
                    Marshal.WriteInt32(instBuf, displacementOffset, displacement);
                    
                    // Complete function if JMP (FF /4)
                    if (opcode == 0xFF && modRMReg == 4)
                        finished = true;
              
                } else if(opcode == 0xE8) {

                    IntPtr dest = (IntPtr)((long)oldInst + inst.Length + inst.Operands[0].LvalSDWord);

                    if (inst.Operands[0].Size != 32) throw new NotSupportedException("Only rel32 calls are supported");
                    copySize = WriteCall(instBuf, newInst, dest, is64);
                    if (is64) absoluteCalls |= 1UL << (int)InstructionBoundaries;
                    copySrc = instBuf;

                }else if( (opcode & 0xFD) == 0xE9) {

                    IntPtr dest = oldInst + inst.Length;

                    if (opcode == 0xEB) {
                        dest = IntPtr.Add(dest, inst.Operands[0].LvalSByte);
                    } else {
                        if (inst.Operands[0].Size != 32) throw new NotSupportedException("Only rel32 near jumps are supported");
                        dest = IntPtr.Add(dest, inst.Operands[0].LvalSDWord);
                    }

                    if((long)Target <= (long)dest && (long)dest < ((long)Target + RelativeJumpSize)) {
                        if((long)jmpDest < (long)dest) {
                            jmpDest = dest;
                        }
                    } else {

                        copySize = WriteJump(instBuf, newInst, dest, is64);
                        copySrc = instBuf;
                        finished = ((long)oldInst >= (long)jmpDest);
                    }


                }else if(inst.Length >= 2 && (
                            ((opcode & 0xF0) == 0x70) ||
                            ((opcode & 0xFC) == 0xE0) ||
                            (opcode == 0x0F && (Marshal.ReadByte(oldInst, opcodeOffset + 1) & 0xF0) == 0x80))) {
                    //Jcc Handler

                    IntPtr dest = oldInst + inst.Length;

                    if( (opcode & 0xF0) == 0x70 || (opcode & 0xFC) == 0xE0) {

                        dest = IntPtr.Add(dest, inst.Operands[0].LvalSByte);
                    } else {
                        if (inst.Operands[0].Size != 32) throw new NotSupportedException("Only rel32 near conditional jumps are supported");
                        dest = IntPtr.Add(dest, (int)inst.Operands[0].LvalUDWord);
                    }

                    if((long)Target <= (long)dest && (long)dest < ((long)Target + RelativeJumpSize)){
                        if((long)jmpDest < (long)dest) {
                            jmpDest = dest;
                        }
                    }else if( (opcode & 0xFC) == 0xE0) {
                        throw new Exception("LOOPx/Jxx to the outside not supported");
                    } else {

                        byte cond = (byte)((opcode != 0x0F ? opcode : Marshal.ReadByte(oldInst, opcodeOffset + 1)) & 0x0F);
                        copySize = WriteConditionalJump(instBuf, newInst, dest, cond, is64);
                        if (is64) absoluteConditionalJumps |= 1UL << (int)InstructionBoundaries;
                        copySrc = instBuf;
                    }

                }else if(inst.Mnemonic == ud_mnemonic_code.UD_Iret || inst.Mnemonic == ud_mnemonic_code.UD_Iretf) {

                    finished = ((long)oldInst >= (long)jmpDest);
                }

                if((long)oldInst < (long)jmpDest && copySize != inst.Length) {
                    throw new Exception("Can't alter intruction length in a branch");
                }

                if((newPos + copySize) > TrampolineMaxSize) {
                    throw new Exception("Trampoline function too big");
                }

                if(InstructionBoundaries >= OldInstructionBoundaries.Length) {
                    throw new Exception("Trampoline has too many instructions");
                }

                OldInstructionBoundaries[InstructionBoundaries] = (byte)oldPos;
                NewInstructionBoundaries[InstructionBoundaries] = (byte)newPos;
                InstructionBoundaries++;

                NativeMemory.Copy((IntPtr)((long)Tramp + newPos), copySrc, (int)copySize);
               
                newPos += copySize;
                oldPos += (uint)inst.Length;            

            } while (!finished);


            if (oldPos < RelativeJumpSize

                && !IsCodePadding((IntPtr)((long)Target + oldPos), (int)(RelativeJumpSize - oldPos))) {

                if (oldPos < ShortJumpSize
                    && !IsCodePadding((IntPtr)((long)Target + oldPos), (int)(ShortJumpSize - oldPos))) {

                    throw new Exception("Not enough space for patch");
                }

                if (!IsExecutableAddress((IntPtr)((long)Target - RelativeJumpSize))) {
                    throw new Exception("Not enought space for patch");
                }

                if (!IsCodePadding((IntPtr)((long)Target - RelativeJumpSize), RelativeJumpSize)) {
                    throw new Exception("Not enought space for patch");
                }

                PatchAbove = true;
            }

            if (is64) {
                Relay = (IntPtr)((long)Tramp + newPos);
                WriteJump(Relay, Relay, Detour, true);
            }

            BackupPrologue();
        }

        void BackupPrologue() {
            
            if (PatchAbove) {

                Marshal.Copy((IntPtr)((long)Target - RelativeJumpSize), Backup, 0, RelativeJumpSize + ShortJumpSize);

            } else {
                Marshal.Copy(Target, Backup, 0, RelativeJumpSize);
            }
        }

        // Boundary mapping follows MinHook v1.3.4 FindOldIP/FindNewIP, with explicit
        // continuations for the extra instructions emitted by x64 CALL/Jcc expansion.
        internal bool TryMapInstructionPointer(ulong ip, bool enable, bool targetIsPatched, out ulong mapped) {
            NativeHookPlan plan = default;
            WriteNativePlan(ref plan, targetIsPatched);
            return NativeThreadMethods.mh_map_ip(ref plan, ip, enable ? 1 : 0, out mapped) != 0;
        }

        internal void WriteNativePlan(ref NativeHookPlan plan, bool enabled) {
            plan.Target = Target;
            plan.Trampoline = Tramp;
            plan.Relay = Relay;
            plan.Destination = IntPtr.Size == 8 ? Relay : Detour;
            plan.AbsoluteCalls = absoluteCalls;
            plan.AbsoluteConditionalJumps = absoluteConditionalJumps;
            plan.BoundaryCount = InstructionBoundaries;
            plan.PatchAbove = PatchAbove ? 1U : 0U;
            plan.Enabled = enabled ? 1U : 0U;
            fixed (NativeHookPlan* value = &plan) {
                for (int i = 0; i < 64; i++) {
                    value->OldIps[i] = OldInstructionBoundaries[i];
                    value->NewIps[i] = NewInstructionBoundaries[i];
                }
                for (int i = 0; i < 8; i++) value->Backup[i] = Backup[i];
            }
        }

        bool IsExecutableAddress(IntPtr address) {
            MEMORY_BASIC_INFORMATION mi = new MEMORY_BASIC_INFORMATION();
            VirtualQuery(address, ref mi, Marshal.SizeOf(mi));
            return (mi.State == MemoryState.Commited && (mi.Protect & PAGE_EXECUTE_FLAGS) > 0);
        }

        bool IsCodePadding(IntPtr codePtr, int len) {
            byte first = Marshal.ReadByte(codePtr);
            if(first != 0x00 && first != 0x90 && first != 0xCC) {
                return false;
            }

            for(int idx = 1; idx < len; ++idx) {
                if (Marshal.ReadByte(codePtr, idx) != first)
                    return false;
            }

            return true;
        }

        static uint WriteJump(IntPtr buffer, IntPtr address, IntPtr destination, bool is64) {
            if (is64) {
                var instruction = new JMP_ABS(destination);
                NativeMemory.Write(buffer, ref instruction);
                return (uint)AbsoluteJumpSize;
            } else {
                var instruction = new JMPCALL_REL(0xE9);
                instruction.SetOperand(unchecked((uint)((long)destination - ((long)address + RelativeJumpSize))));
                NativeMemory.Write(buffer, ref instruction);
                return (uint)RelativeJumpSize;
            }
        }

        static bool IsPrefix(byte opcode, bool is64) {
            return opcode == 0xF0 || opcode == 0xF2 || opcode == 0xF3 ||
                opcode == 0x26 || opcode == 0x2E || opcode == 0x36 || opcode == 0x3E ||
                opcode == 0x64 || opcode == 0x65 || opcode == 0x66 || opcode == 0x67 ||
                (is64 && (opcode & 0xF0) == 0x40);
        }

        static uint WriteCall(IntPtr buffer, IntPtr address, IntPtr destination, bool is64) {
            if (is64) {
                var instruction = new CALL_ABS(destination);
                NativeMemory.Write(buffer, ref instruction);
                return (uint)AbsoluteCallSize;
            } else {
                var instruction = new JMPCALL_REL(0xE8);
                instruction.SetOperand(unchecked((uint)((long)destination - ((long)address + RelativeJumpSize))));
                NativeMemory.Write(buffer, ref instruction);
                return (uint)RelativeJumpSize;
            }
        }

        static uint WriteConditionalJump(IntPtr buffer, IntPtr address, IntPtr destination, byte condition, bool is64) {
            if (is64) {
                var instruction = new JCC_ABS(destination);
                instruction.SetOpcode((byte)(0x71 ^ condition));
                NativeMemory.Write(buffer, ref instruction);
                return (uint)AbsoluteConditionalJumpSize;
            } else {
                var instruction = new JCC_REL(unchecked((uint)((long)destination - ((long)address + RelativeConditionalJumpSize))));
                instruction.SetOpcode((byte)(0x80 | condition));
                NativeMemory.Write(buffer, ref instruction);
                return (uint)RelativeConditionalJumpSize;
            }
        }
    }
}
