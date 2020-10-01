# **docker pwnenv**

**pwnenv** is a series of docker containers that I made, which allow you to run and debug _linux binaries_ with the desired libc.

This is achieved by having **three** different containers with different libc versions (versions of ubuntu):
- Ubuntu 16
- Ubuntu 18
- Ubuntu 20

> Note: The one built on top of Ubuntu 18 is the most tested out of the three.

This was built to run on docker on a Windows 10 machine with _WSL 2_.

This started as a fork of [pwndocker by skysider](https://github.com/skysider/pwndocker)

### **Features**:
- zsh / tmux
- Custom **pwntools** templates for **x86**, **x86-64**, **arm**
- **gdb** with **gef**, **pwndbg**, **peda** ([Article from Andreas Pogiatzis](https://medium.com/bugbountywriteup/pwndbg-gef-peda-one-for-all-and-all-for-one-714d71bf36b8))  
- one_gadget
- seccomp-tools
- reutils
- ropper
- ROPGadget
- main_arena_offset
- heap_inspect
- and many more
---
## Building the containers

To built the container, move the desired **dockerfile** from the dockerfiles directory to the root of the project with the name `Dockerfile` and run the following command to built it.

```powershell
docker build -t <container-name> .
```

> Note: to work with the provided run script the name must be (depending on the container you want to build):
> - `pwnenvarm`
> - `pwnenv16`
> - `pwnenv18`
> - `pwnenv20`


---
## Usage Info

I set this up so the containers can be started from anywhere. The run scripts automatically mount the current directory in the container.

> I added the following code to the **$PROFILE** of powershell, so it creates this function (`pwnenv`) when I open a new PS window.

```powershell
$pwnenv = "<path-to-the-run-folder>"
function pwnenv ($ver, $arguments) {
    if ($ver -eq 16) {& $pwnenv/run_16.ps1 $arguments}
    elseif ($ver -eq 18) {& $pwnenv/run_18.ps1 $arguments}
    elseif ($ver -eq 20) {& $pwnenv/run_20.ps1 $arguments}
    elseif ($ver -eq "arm") {& $pwnenv/run_arm.ps1 $arguments}
}
```

Now just restart powershell, go to the woking directory and type `pwnenv <arm|16|18|20>`
