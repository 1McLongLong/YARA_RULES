rule PasswordSpray_Detection {
    meta:
        description = "Detects potential password spraying in log files"
        author = "Taha"
    strings:
        $failed1 = "failed login" nocase
        $failed2 = "authentication failure" nocase
        $failed3 = "logon failure" nocase
        $ip = /\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b/

    condition:
        any of ($failed*) >= 5 and $ip
}
