using Microsoft.VisualStudio.TestTools.UnitTesting;

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace MinHook.NET.Tests
{
    [TestClass]
    public class HookTests
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        delegate IntPtr OpenProcessDelegate(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        OpenProcessDelegate OpenProcess_orig;

        IntPtr _testValue = (IntPtr)1337;

        IntPtr OpenProcess_Detour(uint processAccess, bool bInheritHandle, int processId)
        {
            return _testValue;
        }

        [TestMethod]
        public void TestOpenProcessHook()
        {
            IntPtr result;

            using (var engine = new HookEngine())
            {

                OpenProcess_orig = engine.CreateHook("kernel32.dll", "OpenProcess", new OpenProcessDelegate(OpenProcess_Detour));
                engine.EnableHooks();

                result = OpenProcess(0x001F0FFF, false, Process.GetCurrentProcess().Id);
            }

            Assert.AreEqual(_testValue, result);
        }
    }
}
