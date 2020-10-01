docker run --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -it --rm --name pwnenv16 -v "$(get-location):/home/pwn/data".ToLower() pwnenv16
