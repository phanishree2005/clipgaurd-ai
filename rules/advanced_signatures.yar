rule APT_Ransomware_Note_String
{
    meta:
        description = "Detects common ransomware note strings in clipboard"
        author = "ClipGuard"
        weight = 10
    strings:
        $s1 = "Your files are encrypted" nocase wide ascii
        $s2 = "pay the ransom" nocase wide ascii
        $s3 = "Bitcoin address:" nocase wide ascii
    condition:
        any of them
}

rule Suspicious_PowerShell_Obfuscation
{
    meta:
        description = "Detects obfuscated PowerShell commands often used by malware"
        author = "ClipGuard"
        weight = 9
    strings:
        $ps1 = "IEX" nocase
        $ps2 = "Invoke-Expression" nocase
        $ps3 = "[Convert]::FromBase64String" nocase
        $ps4 = "Hidden -Command" nocase
    condition:
        2 of them
}

rule Potential_SQL_Injection
{
    meta:
        description = "Detects common SQL injection patterns"
        author = "ClipGuard"
        weight = 8
    strings:
        $sql1 = "' OR '1'='1" nocase
        $sql2 = "UNION SELECT" nocase
        $sql3 = "WAITFOR DELAY" nocase
    condition:
        any of them
}
