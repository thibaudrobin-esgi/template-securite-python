rule windows_shell_exec
{
    meta:
        description = "Appel à un interpréteur de commandes Windows"
    strings:
        $cmd = "cmd.exe" nocase
        $ps = "powershell" nocase
        $wscript = "wscript.exe" nocase
    condition:
        any of them
}

rule base64_powershell
{
    meta:
        description = "PowerShell encodé en base64 (-enc)"
    strings:
        $enc = "-enc" nocase
        $eb = "-EncodedCommand" nocase
    condition:
        any of them
}

rule upx_packer
{
    meta:
        description = "Binaire packé avec UPX"
    strings:
        $upx0 = "UPX0"
        $upx1 = "UPX1"
    condition:
        all of them
}

rule credential_access
{
    meta:
        description = "Chaînes liées au vol d'identifiants"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "lsass" nocase
    condition:
        any of them
}

rule persistence_run_key
{
    meta:
        description = "Persistance via clé Run du registre"
    strings:
        $run = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        $run
}

rule suspicious_downloader
{
    meta:
        description = "Téléchargement de charge secondaire (downloader)"
    strings:
        $urlmon = "urlmon.dll" nocase
        $dl = "URLDownloadToFile" nocase
        $inet = "InternetOpen" nocase
        $wininet = "wininet.dll" nocase
    condition:
        any of them
}

rule process_injection
{
    meta:
        description = "Injection de code dans un autre processus"
    strings:
        $crt = "CreateRemoteThread" nocase
        $vae = "VirtualAllocEx" nocase
        $wpm = "WriteProcessMemory" nocase
    condition:
        2 of them
}
