set debuginfod enabled on
source /root/ctf-tools/heapinspect/gdbscript.py

set step-mode on
define init-peda
source ~/peda/peda.py
end
document init-peda
Initializes the PEDA (Python Exploit Development Assistant for GDB) framework
end

define init-pwndbg
source ~/.gdbinit_pwndbg
set debuginfod enabled on
end
document init-pwndbg
Initializes PwnDBG
end

define init-gef
source ~/.gdbinit-gef.py
end
document init-gef
Initializes GEF (GDB Enhanced Features)
end
