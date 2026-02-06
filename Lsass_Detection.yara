rule Lsass_Detection {
    meta:
        description = "Detects LSASS process memory dump files"
        author = "Taha"
    strings:
    $mdmp = { 4D 44 4D 50 }
    $lsass = "lsass.exe" nocase
    $lsass2 = "lsarv.dll" nocase
    $lsass3 = "wdigest.dll" nocase
    $lsass4 = "kerberos.dll" nocase
    $lsass5 = "msv1_0.dll" nocase
    $lsass6 = "lsass.exe" wide nocase  
    condition:
        $mdmp at 0 and 2 of ($lsass*)
}

rule Mimikatz_Tool_Detection
{
    meta:
        description = "Detects Mimikatz credential dumping tool"
    strings:
        $s1 = "sekurlsa::logonpasswords" nocase
        $s2 = "gentilkiwi" nocase
        $s3 = "mimikatz" nocase
        $s4 = "privilege::debug" nocase
        $s5 = "lsadump::sam" nocase
        
    condition:
        2 of them
}

rule Procdump_LSASS_Dump
{
    meta:
        description = "Detects procdump targeting LSASS"
    strings:
        $cmd1 = "procdump" nocase
        $cmd2 = "-ma lsass" nocase
        $cmd3 = "lsass.exe" nocase
        $cmd4 = "lsass.dmp" nocase
        
    condition:
        $cmd1 and ($cmd2 or ($cmd3 and $cmd4))
}