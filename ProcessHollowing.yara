rule ProcessHollowing {
    meta:
        description = "Detects potential process hollowing techniques"
        author = "Taha"
    strings:
        $mz = { 4D 5A }
        $pe = { 50 45 00 00 }

        $api1 = "NtUnmapViewOfSection"
        $api2 = "WriteProcessMemory"
        $api3 = "VirtualAllocEx"
        $api4 = "ResumeThread"
    condition:
        $mz at 0 and $pe and 2 of ($api*)
}
