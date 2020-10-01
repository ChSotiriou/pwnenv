docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm --name pwnenvarm -v "$(get-location):/home/pwn/data".ToLower() pwnenvarm 
