rule PowerShell_GzipObfuscation {
    meta:
        description = "Detect Multi-layer gzip obfuscation in PowerShell scripts"
        author = "Taha"
    strings:
        $base64gzip = "H4sI" nocase
        $gzip1 = "GzipStream" nocase
        $gzip2 = "FromBase64String" nocase
        $gzip3 = "System.IO.Compression" nocase
        $gzip4 = "IO.MemoryStream" nocase

    condition:
        $base64gzip and 3 of ($gzip*)
}
