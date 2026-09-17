/*
   Node.js 后门检测规则
*/

rule NodeJS_Command_Execution
{
    meta:
        description = "Node.js 命令执行后门"
        severity = "critical"
        author = "sec_audit"
    strings:
        $child_process = "child_process" nocase
        $exec = "exec(" nocase
        $spawn = "spawn(" nocase
        $require = "require(" nocase
        $request = "req." nocase
        $eval = "eval(" nocase
    condition:
        ($child_process and ($exec or $spawn)) or
        ($require and $child_process) or
        ($eval and $request)
}

rule NodeJS_Dynamic_Eval
{
    meta:
        description = "Node.js 动态代码执行"
        severity = "high"
        author = "sec_audit"
    strings:
        $new_function = "new Function(" nocase
        $eval = "eval(" nocase
        $vm = "require('vm')" nocase
        $vm2 = "require(\"vm\")" nocase
    condition:
        $new_function or $eval or $vm or $vm2
}