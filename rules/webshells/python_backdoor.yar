/*
   Python 后门检测规则
*/

rule Python_Reverse_Shell
{
    meta:
        description = "Python 反弹 Shell"
        severity = "critical"
        author = "sec_audit"
    strings:
        $socket = "socket.socket(" nocase
        $connect = "connect(" nocase
        $subprocess = "subprocess." nocase
        $pty = "pty.spawn" nocase
        $os_system = "os.system(" nocase
    condition:
        ($socket and $connect and $subprocess) or
        ($socket and $connect and $pty) or
        ($socket and $connect and $os_system)
}

rule Python_Command_Execution
{
    meta:
        description = "Python 命令执行后门"
        severity = "high"
        author = "sec_audit"
    strings:
        $eval = "eval(" nocase
        $exec = "exec(" nocase
        $request = "request." nocase
        $input = "input(" nocase
        $argv = "sys.argv" nocase
    condition:
        ($eval or $exec) and
        ($request or $input or $argv)
}

rule Python_Pickle_Deserialization
{
    meta:
        description = "Python 反序列化风险"
        severity = "high"
        author = "sec_audit"
    strings:
        $pickle = "pickle.loads" nocase
        $cPickle = "cPickle.loads" nocase
        $yaml = "yaml.load(" nocase
        $marshal = "marshal.loads" nocase
        $request = "request." nocase
    condition:
        ($pickle or $cPickle or $yaml or $marshal) and
        $request
}