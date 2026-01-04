rule SQL_Injection {
    meta:
        description = "Detects common SQL Injection patterns"
        author = "AlertForge"
        severity = "High"
    strings:
        $s1 = "union select" nocase
        $s2 = /or\s+['"]?1['"]?=['"]?1/ nocase
        $s3 = "drop table" nocase
        $s4 = "delete from" nocase
        $s5 = /admin'\s*(--|#)/ nocase
        $s6 = /'\s*or\s*'[\d\w]+'=['"]?[\d\w]+/ nocase
        $s7 = "waitfor delay" nocase
    condition:
        any of them
}

rule XSS_Attack {
    meta:
        description = "Detects Cross-Site Scripting (XSS) attempts"
        author = "AlertForge"
        severity = "Medium"
    strings:
        $s1 = "<script>" nocase
        $s2 = "javascript:" nocase
        $s3 = "alert(" nocase
        $s4 = "onerror=" nocase
        $s5 = "onload=" nocase
    condition:
        any of them
}

rule Path_Traversal {
    meta:
        description = "Detects Directory Traversal attempts"
        author = "AlertForge"
        severity = "High"
    strings:
        $s1 = "../"
        $s2 = "..\\"
        $s3 = "/etc/passwd"
        $s4 = "c:\\windows\\system32" nocase
    condition:
        any of them
}

rule Webshell_Indicator {
    meta:
        description = "Detects common keywords associated with PHP/ASP webshells"
        author = "AlertForge"
        severity = "Critical"
    strings:
        $s1 = "c99shell" nocase
        $s2 = "r57shell" nocase
        $s3 = "b374k" nocase
        $s4 = "cmd.exe" nocase
        $s5 = "eval(base64_decode"
        $s6 = "shell_exec"
        $s7 = "/bin/sh"
    condition:
        any of them
}

rule Crypto_Miner {
    meta:
        description = "Detects indicators of crypto mining activity"
        author = "AlertForge"
        severity = "High"
    strings:
        $s1 = "stratum+tcp" nocase
        $s2 = "xmrig" nocase
        $s3 = "minerd" nocase
        $s4 = "cryptonight" nocase
    condition:
        any of them
}
