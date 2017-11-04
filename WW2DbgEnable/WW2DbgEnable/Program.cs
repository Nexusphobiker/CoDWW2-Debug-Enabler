using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace WW2DbgEnable
{
    class Program
    {
        //cod ww2 debug enabler
        /*Sledgehammered functions:
        MODUL: KERNEL32
        CopyFileExW
        MODUL: ntdll
        DbgBreakPoint
        DbgUserBreakPoint
        DbgUiConnectToDbg
        DbgUiContinue
        DbgUiConvertStateChangeStructure
        DbgUiDebugActiveProcess
        DbgUiGetThreadDebugObject
        DbgUiIssueRemoteBreakin
        DbgUiRemoteBreakin
        DbgUiSetThreadDebugObject
        DbgUiStopDebugging
        DbgUiWaitStateChange
        DbgPrintReturnControlC
        DbgPrompt*/
        static void Main(string[] args)
        {
            string[] sledgehammeredFuncs = { "DbgBreakPoint", "DbgUserBreakPoint", "DbgUiConnectToDbg", "DbgUiContinue", "DbgUiConvertStateChangeStructure", "DbgUiDebugActiveProcess", "DbgUiGetThreadDebugObject", "DbgUiIssueRemoteBreakin", "DbgUiRemoteBreakin", "DbgUiSetThreadDebugObject", "DbgUiStopDebugging", "DbgUiWaitStateChange", "DbgPrintReturnControlC", "DbgPrompt" };
            Console.WriteLine("hacking into mainframe...");
            Process[] process = Process.GetProcessesByName("s2_mp64_ship");
            if(process.Length <= 0)
            {
                Console.WriteLine("Target not found");
                Console.ReadKey();
                return;
            }
            //Should only be one active anyways so we take the first process and get the ntdll module handle
            IntPtr externKernel32Handle = GetModulHandleEx(process.First(), "kernel32.dll");
            IntPtr externNtdllHandle = GetModulHandleEx(process.First(), "ntdll.dll");
            if(externKernel32Handle == IntPtr.Zero || externNtdllHandle == IntPtr.Zero)
            {
                Console.WriteLine("hacking into mainframe failed. sub matrix not found (ntdll:"+ (externNtdllHandle == IntPtr.Zero) + " kernel32:"+ (externKernel32Handle == IntPtr.Zero) + ")");
                Console.ReadKey();
                return;
            }
            Console.WriteLine("attempting to crawl subconsciousness...");
            //get all addresses of functions which got overwritten and remove the jmps
            IntPtr localKernel32Handle = GetModuleHandle("kernel32.dll");
            IntPtr localNtdllHandle = GetModuleHandle("ntdll.dll");
            if(localNtdllHandle == IntPtr.Zero || localKernel32Handle == IntPtr.Zero)
            {
                Console.WriteLine("crawling subconsciousness failed. (ntdll:"+ (localNtdllHandle == IntPtr.Zero) + " kernel32:"+ (localKernel32Handle == IntPtr.Zero) + ")");
                Console.ReadKey();
                return;
            }
            Console.WriteLine("Executing \"win.exe\" ");
            IntPtr gameHandle = OpenProcess(ProcessAccessFlags.All, false, process.First().Id);
            try {
            //Only one function in Kernel32 so no loop needed
            int numWritten = 0;
            IntPtr cleanAddress = GetProcAddress(localKernel32Handle, "CopyFileExW");
            byte[] byteBuff = new byte[14];
            Marshal.Copy(cleanAddress, byteBuff, 0, byteBuff.Length);
            WriteProcessMemory(gameHandle, GetProcAddress(externKernel32Handle, "CopyFileExW"), byteBuff, byteBuff.Length, ref numWritten);
            foreach (string funcName in sledgehammeredFuncs)
                {
                Console.WriteLine("F:" + funcName + " ");
                cleanAddress = GetProcAddress(localNtdllHandle, funcName);
                Marshal.Copy(cleanAddress, byteBuff, 0, byteBuff.Length);
                WriteProcessMemory(gameHandle, GetProcAddress(externNtdllHandle, funcName), byteBuff, byteBuff.Length, ref numWritten);
            }
            }
            catch(Exception ex)
            {
                Console.WriteLine("exception while winning. Turns out the only winning move is not to play. "+ex.Message);
            }
            Console.ReadKey();
        }

        //Credit to http://www.pinvoke.net/default.aspx/psapi.enumprocessmodules
        static IntPtr GetModulHandleEx(Process process, string modulname)
        {
            IntPtr ret = IntPtr.Zero;
            // Setting up the variable for the second argument for EnumProcessModules
            IntPtr[] hMods = new IntPtr[1024];

            GCHandle gch = GCHandle.Alloc(hMods, GCHandleType.Pinned); // Don't forget to free this later
            IntPtr pModules = gch.AddrOfPinnedObject();

            // Setting up the rest of the parameters for EnumProcessModules
            uint uiSize = (uint)(Marshal.SizeOf(typeof(IntPtr)) * (hMods.Length));
            uint cbNeeded = 0;

            if (EnumProcessModules(process.Handle, pModules, uiSize, out cbNeeded) == 1)
            {
                Int32 uiTotalNumberofModules = (Int32)(cbNeeded / (Marshal.SizeOf(typeof(IntPtr))));

                for (int i = 0; i < (int)uiTotalNumberofModules; i++)
                {
                    StringBuilder strbld = new StringBuilder(1024);
                    GetModuleFileNameEx(process.Handle, hMods[i], strbld, strbld.Capacity);
                    if (strbld.ToString().ToLower().Contains(modulname))
                    {
                        Console.WriteLine(modulname + " found!");
                        Console.WriteLine("File Path: " + strbld.ToString());
                        ret = hMods[i];
                        break;
                    }
                }
            }

            // Must free the GCHandle object
            gch.Free();
            return ret;
        }

        //mostly c&p from http://www.pinvoke.net/
        #region WINAPI 
        [DllImport("psapi.dll", CallingConvention = CallingConvention.StdCall, SetLastError = true)]
        static extern int EnumProcessModules(IntPtr hProcess, [Out] IntPtr lphModule, uint cb, out uint lpcbNeeded);

        [DllImport("psapi.dll", SetLastError = true)]
        static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, StringBuilder lpFilename, int nSize);

        [DllImport("Kernel32.dll", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, ref int lpNumberOfBytesWritten);

        [Flags]
        public enum ProcessAccessFlags : uint
        {
            All = 0x001F0FFF,
            Terminate = 0x00000001,
            CreateThread = 0x00000002,
            VirtualMemoryOperation = 0x00000008,
            VirtualMemoryRead = 0x00000010,
            VirtualMemoryWrite = 0x00000020,
            DuplicateHandle = 0x00000040,
            CreateProcess = 0x000000080,
            SetQuota = 0x00000100,
            SetInformation = 0x00000200,
            QueryInformation = 0x00000400,
            QueryLimitedInformation = 0x00001000,
            Synchronize = 0x00100000
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId );
        #endregion
    }
}
