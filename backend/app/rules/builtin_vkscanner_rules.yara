
rule vk_maldoc_persistence {
    meta:
        category = "Autostart / Persistence"
        severity = "high"
        score_impact = 20
    strings:
        $autoopen = "AutoOpen" nocase
        $autoexec = "AutoExec" nocase
        $docopen = "Document_Open" nocase
        $workopen = "Workbook_Open" nocase
        $auto_open = "Auto_Open" nocase
        $docclose = "Document_Close" nocase
        $workclose = "Workbook_Close" nocase
        $autoclose = "AutoClose" nocase
    condition:
        any of them
}

rule vk_maldoc_execution {
    meta:
        category = "Command Execution"
        severity = "critical"
        score_impact = 35
    strings:
        $shell = /Shell[ \t]*\(/ nocase
        $wscript = "WScript.Shell" nocase
        $shell_app = "Shell.Application" nocase
        $powershell = "Powershell" nocase
        $cmd = "cmd.exe" nocase
        $rundll = "rundll32" nocase
        $regsvr = "regsvr32" nocase
        $mshta = "mshta" nocase
        $bitsadmin = "bitsadmin" nocase
        $certutil = "certutil" nocase
    condition:
        any of them
}

rule vk_maldoc_network {
    meta:
        category = "Network Downloader"
        severity = "critical"
        score_impact = 30
    strings:
        $url_down = "URLDownloadToFile" nocase
        $xmlhttp = "XMLHTTP" nocase
        $winhttp = "WinHttpRequest" nocase
        $net_open = "InternetOpen" nocase
        $net_url = "InternetOpenUrl" nocase
    condition:
        any of them
}

rule vk_maldoc_system {
    meta:
        category = "System Object Manipulation"
        severity = "medium"
        score_impact = 15
    strings:
        $adodb = "ADODB.Stream" nocase
        $environ = "environ" nocase
        $create = "CreateObject" nocase
        $get = "GetObject" nocase
        $callby = "CallByName" nocase
    condition:
        any of them
}

rule vk_maldoc_memory {
    meta:
        category = "Memory/Process Injection API"
        severity = "critical"
        score_impact = 40
    strings:
        $valloc = "VirtualAlloc" nocase
        $vprotect = "VirtualProtect" nocase
        $rtlmove = "RtlMoveMemory" nocase
        $copy = "CopyMemory" nocase
        $cthread = "CreateThread" nocase
        $wprocess = "WriteProcessMemory" nocase
    condition:
        any of them
}

rule vk_maldoc_obfuscation {
    meta:
        category = "Code Obfuscation"
        severity = "high"
        score_impact = 25
    strings:
        $reverse = "StrReverse" nocase
        $c_func = "Chr(" nocase
        $cw_func = "ChrW(" nocase
    condition:
        $reverse or #c_func >= 5 or #cw_func >= 5
}

rule vk_maldoc_embedded_pe {
    meta:
        category = "Embedded Executable (PE File)"
        severity = "critical"
        score_impact = 45
    strings:
        $dos_mode = "This program cannot be run in DOS mode" nocase
        $mz_hex = "4d5a900003000000" nocase
    condition:
        any of them
}

rule vk_offensive_impacket {
    meta:
        category = "Offensive Tool / Impacket"
        severity = "critical"
        score_impact = 45
    strings:
        $imp_dce = "impacket.dcerpc" nocase
        $imp_smb = "impacket.smb" nocase
        $imp_ntlm = "impacket.ntlm" nocase
        $imp_ldap = "impacket.ldap" nocase
        $imp_secrets = "secretsdump" nocase
        $imp_wmi = "wmiexec" nocase
        $imp_psexec = "psexec" nocase
    condition:
        any of them
}

rule vk_offensive_powershell {
    meta:
        category = "Offensive PowerShell Script"
        severity = "critical"
        score_impact = 40
    strings:
        $iex = "IEX" nocase
        $iex_full = "Invoke-Expression" nocase
        $bypass = "bypass" nocase
        $exec_pol = "ExecutionPolicy" nocase
        $webclient = "Net.WebClient" nocase
        $down_str = "DownloadString" nocase
        $down_file = "DownloadFile" nocase
        $tcp_client = "System.Net.Sockets.TCPClient" nocase
        $enc_cmd = "EncodedCommand" nocase
        $hidden = "-w hidden" nocase
        $nop = "-nop" nocase
    condition:
        (any of ($iex, $iex_full) and any of ($webclient, $down_str, $down_file)) or
        (any of ($tcp_client, $enc_cmd)) or
        (any of ($hidden, $nop) and any of ($bypass, $exec_pol))
}

rule vk_offensive_reverse_shell {
    meta:
        category = "Reverse Shell / Backdoor"
        severity = "critical"
        score_impact = 45
    strings:
        $rev_bash1 = "bash -i >& /dev/tcp/" nocase
        $rev_bash2 = "bash -i >& /dev/udp/" nocase
        $rev_sh = "sh -i" nocase
        $sock_conn = /socket\.connect\(\(\s*['\"][0-9\.]+['\"],\s*[0-9]+\s*\)\)/ nocase
        $py_sock = "import socket" nocase
        $py_sub = "subprocess.Popen" nocase
        $py_dup = "os.dup2" nocase
    condition:
        any of ($rev_bash1, $rev_bash2, $rev_sh, $sock_conn) or
        (all of ($py_sock, $py_sub, $py_dup))
}

rule vk_offensive_shell_script {
    meta:
        category = "Offensive Shell Script"
        severity = "high"
        score_impact = 35
    strings:
        $sh_bin = "#!/bin/sh"
        $bash_bin = "#!/bin/bash"
        $dev_tcp = "/dev/tcp/"
        $dev_udp = "/dev/udp/"
        $mkfifo = "mkfifo"
        $backpipe = "backpipe"
    condition:
        (any of ($sh_bin, $bash_bin) and any of ($dev_tcp, $dev_udp, $mkfifo, $backpipe))
}
