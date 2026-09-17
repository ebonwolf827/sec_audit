/*
   ASP/ASPX Webshell 检测规则
   来源: 自定义 + 参考 Neo23x0/signature-base gen_webshells.yar
*/

rule ASPX_Command_Execution
{
    meta:
        description = "ASPX 命令执行 Webshell"
        severity = "critical"
        author = "sec_audit"
    strings:
        $page = "<%@ Page" nocase
        $process = "Process.Start" nocase
        $cmd = "cmd.exe" nocase
        $request = "Request[" nocase
        $eval = "eval(" nocase
    condition:
        filesize < 5000 and
        $page and
        ($process or $eval) and
        ($cmd or $request)
}

rule ASP_Webshell_Generic
{
    meta:
        description = "ASP Webshell 通用特征"
        severity = "high"
        author = "sec_audit"
    strings:
        $asp_tag = "<%" ascii
        $create = "Server.CreateObject" nocase
        $shell = "WScript.Shell" nocase
        $exec = "Exec(" nocase
        $request = "Request(" nocase
    condition:
        filesize < 3000 and
        $asp_tag and
        $create and
        ($shell or $exec) and
        $request
}
