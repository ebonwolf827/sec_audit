/*
   PHP Webshell 检测规则
   来源: 自定义 + 参考 Neo23x0/signature-base gen_webshells.yar
   许可: Detection Rule License 1.1
*/

rule PHP_OneLine_Webshell
{
    meta:
        description = "PHP 一句话木马"
        severity = "critical"
        author = "sec_audit"
        reference = "https://github.com/Neo23x0/signature-base"
    strings:
        $eval    = "eval(" nocase
        $assert  = "assert(" nocase
        $system  = "system(" nocase
        $exec    = "exec(" nocase
        $shell   = "shell_exec(" nocase
        $passthru = "passthru(" nocase
        $post    = "$_POST" nocase
        $get     = "$_GET" nocase
        $request = "$_REQUEST" nocase
        $cookie  = "$_COOKIE" nocase
    condition:
        filesize < 500 and
        ($eval or $assert or $system or $exec or $shell or $passthru) and
        ($post or $get or $request or $cookie)
}

rule PHP_Obfuscated_Webshell
{
    meta:
        description = "PHP 混淆编码 Webshell"
        severity = "critical"
        author = "sec_audit"
    strings:
        $base64  = "base64_decode" nocase
        $gzinflate = "gzinflate" nocase
        $str_rot13 = "str_rot13" nocase
        $post    = "$_POST" nocase
        $get     = "$_GET" nocase
        $request = "$_REQUEST" nocase
        $long_b64 = /[A-Za-z0-9+\/]{200,}={0,2}/ ascii
    condition:
        ($base64 or $gzinflate or $str_rot13) and
        ($post or $get or $request) and
        ($long_b64 or filesize < 1000)
}

rule PHP_C99_Shell
{
    meta:
        description = "C99 Webshell"
        severity = "critical"
        author = "sec_audit"
        reference = "https://www.c99shell.info"
    strings:
        $s1 = "c99shell" nocase
        $s2 = "c99.php" nocase
        $s3 = "C99Shell" nocase
        $s4 = "phpMyAdmin" nocase
        $s5 = "$_SERVER['HTTP_" nocase
    condition:
        any of ($s*) and filesize > 10KB
}

rule PHP_Webshell_Generic
{
    meta:
        description = "PHP Webshell 通用特征"
        severity = "high"
        author = "sec_audit"
    strings:
        $php_tag = "<?php" nocase
        $f1 = "eval" ascii
        $f2 = "assert" ascii
        $f3 = "system" ascii
        $f4 = "passthru" ascii
        $f5 = "shell_exec" ascii
        $f6 = "popen" ascii
        $f7 = "proc_open" ascii
        $input = "$_REQUEST" ascii
    condition:
        filesize < 5000 and
        ($php_tag in (0..100)) and
        2 of ($f*) and
        $input
}