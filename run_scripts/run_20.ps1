docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm --name pwnenv20 -v "$(get-location):/home/pwn/data".ToLower() pwnenv20
