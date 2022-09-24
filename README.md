# **docker pwnenv**

**pwnenv** is a series of docker containers that I made, which allow you to run and debug _linux binaries_ with the desired libc.

## Changelog

1. Switched out the 3 containers for 1
2. Updated vimrc and zshrc
3. Removed non privilaged user (everything happens with the root user)

This started as a fork of [pwndocker by skysider](https://github.com/skysider/pwndocker)

### **Features**:
- zsh / tmux
- Custom **pwntools** templates for **x86**, **x86-64**, **arm**
- **gdb** with **gef**, **pwndbg**, **peda** ([Article from Andreas Pogiatzis](https://medium.com/bugbountywriteup/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8))
- rizin
- rz-ghidra
- one_gadget
- seccomp-tools
- reutils
- ropper
- ROPGadget
- main_arena_offset
- heap_inspect
- and many more
---
## Building / Downloading the containers

```bash
# Download From DockerHub
docker pull jojo1216/pwnenv

# or Bulding From Dockerfile
docker build -t <container-name> .
```
---

## Usage Info

### Windows (Powershell)

I set this up so the containers can be started from anywhere. The run scripts automatically mount the current directory in the container.

> I added the following code to the **$PROFILE** of powershell, so it creates this function (`pwnenv`) when I open a new PS window.

```powershell
$pwnenv = "<path-to-the-run-folder>"
function pwnenv ($arguments) {
    & $pwnenv/run.ps1 $arguments
}
```

Now just restart powershell, go to the woking directory and type `pwnenv`

### Linux

For linux I do it by having the following two functions in the zshrc/bashrc file:

```bash
function checkContainerRunning() {
    docker container ls -q -f name="$1"
}

function pwnenv() {
    if [ $(checkContainerRunning "pwnenv") ]; then
        docker exec -it pwnenv zsh
    else
        docker run --net=host --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm --name "pwnenv" -v "$(pwd)":/root/data "pwnenv"
    fi
}
```

This starts up the container if it is not running or executes bash if it is.
