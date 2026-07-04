/*
general.yar
===========
Basic YARA rules for common malware detection
Author: Ritesh Vijay Bavaskar

How YARA works:
- Each 'rule' defines patterns to look for in a file
- If patterns match -> file is flagged
- 'strings' section defines what to look for
- 'condition' section defines when to trigger
*/

rule Ransomware_Generic
{
    meta:
        description = "Detects generic ransomware indicators"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "high"

    strings:
        $ransom1 = "your files have been encrypted" nocase
        $ransom2 = "pay bitcoin" nocase
        $ransom3 = "HOW_TO_DECRYPT" nocase
        $ransom4 = "your documents, photos, databases" nocase
        $ransom5 = "decrypt your files" nocase
        $ransom6 = "ransomware" nocase

    condition:
        any of them
}


rule Phishing_Document
{
    meta:
        description = "Detects phishing indicators in documents"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "high"

    strings:
        $phish1 = "verify your account" nocase
        $phish2 = "click here immediately" nocase
        $phish3 = "account suspended" nocase
        $phish4 = "update your payment" nocase
        $phish5 = "confirm your identity" nocase
        $phish6 = "unusual activity detected" nocase

    condition:
        2 of them
}


rule Suspicious_PowerShell
{
    meta:
        description = "Detects obfuscated or suspicious PowerShell usage"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "medium"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "-EncodedCommand" nocase
        $ps3 = "IEX" nocase
        $ps4 = "Invoke-Expression" nocase
        $ps5 = "DownloadString" nocase
        $ps6 = "bypass" nocase
        $ps7 = "hidden" nocase

    condition:
        $ps1 and 2 of ($ps2, $ps3, $ps4, $ps5, $ps6, $ps7)
}


rule Malware_Process_Injection
{
    meta:
        description = "Detects process injection techniques"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "high"

    strings:
        $inj1 = "CreateRemoteThread"
        $inj2 = "VirtualAllocEx"
        $inj3 = "WriteProcessMemory"
        $inj4 = "OpenProcess"
        $inj5 = "NtCreateThreadEx"

    condition:
        2 of them
}


rule Keylogger_Indicators
{
    meta:
        description = "Detects potential keylogger behavior"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "high"

    strings:
        $key1 = "SetWindowsHookEx"
        $key2 = "GetAsyncKeyState"
        $key3 = "keylog" nocase
        $key4 = "keystroke" nocase
        $key5 = "GetForegroundWindow"

    condition:
        2 of them
}


rule Suspicious_Network_Activity
{
    meta:
        description = "Detects suspicious network communication patterns"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "medium"

    strings:
        $net1 = "WSAStartup"
        $net2 = "InternetOpenUrl" nocase
        $net3 = "HttpSendRequest" nocase
        $net4 = "command and control" nocase
        $net5 = "reverse shell" nocase
        $net6 = "backdoor" nocase

    condition:
        2 of them
}


rule EICAR_Test_File
{
    meta:
        description = "Detects EICAR antivirus test file"
        author      = "Ritesh Vijay Bavaskar"
        severity    = "low"

    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    condition:
        $eicar
}