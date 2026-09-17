/*
   Java/JSP Webshell 检测规则
   来源: 自定义 + 参考 leonardosmoutinho/yara-detection-rules
*/

rule JSP_Command_Execution
{
    meta:
        description = "JSP 命令执行 Webshell"
        severity = "critical"
        author = "sec_audit"
    strings:
        $jsp_tag = "<%" ascii
        $runtime = "Runtime.getRuntime().exec" nocase
        $process = "new ProcessBuilder" nocase
        $request = "request.getParameter" nocase
        $class_loader = "ClassLoader" nocase
        $define_class = "defineClass" nocase
    condition:
        filesize < 5000 and
        $jsp_tag and
        ($runtime or $process) and
        ($request or $define_class)
}

rule JSP_Reverse_Shell
{
    meta:
        description = "JSP 反弹 Shell"
        severity = "critical"
        author = "sec_audit"
    strings:
        $jsp_tag = "<%" ascii
        $socket = "Socket(" nocase
        $exec = "exec(" nocase
        $inputstream = "getInputStream" nocase
        $process = "Process" nocase
    condition:
        filesize < 5000 and
        $jsp_tag and
        $socket and
        $exec and
        ($inputstream or $process)
}

rule JSP_ClassLoader_Webshell
{
    meta:
        description = "JSP 通过 ClassLoader 动态加载类（内存马特征）"
        severity = "critical"
        author = "sec_audit"
    strings:
        $define = "defineClass" nocase
        $base64 = "base64" nocase
        $input = "request.getParameter" nocase
        $class = "ClassLoader" nocase
    condition:
        $define and
        $class and
        ($base64 or $input)
}

rule WAR_Backdoor
{
    meta:
        description = "WAR 包中的可疑类"
        severity = "high"
        author = "sec_audit"
    strings:
        $war_magic = { 50 4B 03 04 }  // ZIP 魔数
        $servlet = "javax.servlet" ascii
        $filter = "javax.servlet.Filter" ascii
        $listener = "javax.servlet.ServletRequestListener" ascii
        $exec = "Runtime" ascii
        $process = "ProcessBuilder" ascii
    condition:
        $war_magic at 0 and
        ($servlet or $filter or $listener) and
        ($exec or $process)
}