rule obfuscation_detection {
    meta:
        description = "Detects potential command obfuscation techniques"
        author = "Taha"
    strings:
        $escape_chars = /(\^.){5,}/
        $enc_short = "-enc" nocase
        $enc_full = "-EncodedCommand" nocase
        $iex = "iex" nocase
        $invoke_expr = "Invoke-Expression" nocase
        $char_cast = "[char]" nocase
        $download = "DownloadString" nocase
        $hidden = "-w hidden" nocase
        $webclient = "New-Object Net.WebClient" nocase
        $b64_decode = "FromBase64String" nocase

    condition:
        any of ($enc_short, $enc_full)
        or ($iex and $download)
        or ($invoke_expr and $b64_decode)
        or (#char_cast >= 3)
        or ($hidden and $download)
        or ($webclient and $download)
        or #escape_chars >= 1
}