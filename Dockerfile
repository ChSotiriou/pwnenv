FROM ubuntu:24.04

# ----- Setup Enviornment ----- #
# get basics
USER root
ENV HOME=/root
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get upgrade -y  && \
    apt-get update && \
    apt-get install -y \
    # core
    coreutils\
    wget\
    curl\
    git\
    zsh\
    tmux\
    xclip\
    unzip\
    file\
    ltrace\
    strace\
    # build tools
    build-essential\
    gcc\
    g++\
    clang\
    pkg-config\
    llvm\
    cmake\
    binutils-multiarch\
    musl\
    musl-tools\
    # connectivity
    sshpass\
    sshfs\
    socat\
    netcat-openbsd\
    # qemu
    qemu-user\
    qemu-kvm\
    valgrind

# Tooling
RUN apt-get update && \
    apt-get install -y\
    python3\
    ruby\
    ruby-dev\
    # debugging
    libgmp-dev\
    texinfo\
    libc6-armel-cross\
    gcc-arm-linux-gnueabihf\
    gcc-10-arm-linux-gnueabi\
    gdb\
    gdbserver\
    gdb-multiarch\
    clangd\
    # ctfmate
    patchelf\
    elfutils
 
RUN apt update && \
    apt install -y build-essential libssl-dev zlib1g-dev \
    libbz2-dev libreadline-dev libsqlite3-dev curl git \
    libncursesw5-dev xz-utils tk-dev libxml2-dev libxmlsec1-dev libffi-dev liblzma-dev && \
    curl https://pyenv.run | bash
ENV PYENV_ROOT=$HOME/.pyenv
ENV PATH=$PYENV_ROOT/shims:$PYENV_ROOT/bin:$PATH
RUN pyenv install 3.12 && pyenv global 3.12

# configure python(s)
RUN python3 -m pip install --upgrade setuptools
ENV PATH=${HOME}/.local/bin:${PATH}

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH=${HOME}/.cargo/bin:${PATH}

# Support Unicode Characters (https://github.com/itzg/docker-minecraft-server/issues/2164)
RUN apt-get update -y && apt-get install -y locales
RUN echo en_US.UTF-8 UTF-8 > /etc/locale.gen
RUN dpkg-reconfigure --frontend=noninteractive locales

# zsh
WORKDIR /root
COPY files/zsh/.zshrc /root/.zshrc
RUN git clone https://github.com/robbyrussell/oh-my-zsh.git ~/.oh-my-zsh &&\
    chsh -s /bin/zsh && \
    git clone https://github.com/zsh-users/zsh-syntax-highlighting.git "$HOME/.zsh-syntax-highlighting" --depth 1 && \
    git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions && \
    git clone https://github.com/dracula/zsh.git ${HOME}/.oh-my-zsh/themes/dracula && \
    ln -s /root/.oh-my-zsh/themes/dracula/dracula.zsh-theme /root/.oh-my-zsh/themes/dracula.zsh-theme && \
    echo "source $HOME/.zsh-syntax-highlighting/zsh-syntax-highlighting.zsh" >> "$HOME/.zshrc" && \
    echo "source ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions/zsh-autosuggestions.zsh" >> "$HOME/.zshrc"

# tmux
WORKDIR /root
COPY files/tmux /root/.config/tmux

# setup vim to be awesome
RUN wget https://github.com/neovim/neovim/releases/download/v0.10.2/nvim-linux64.tar.gz -O /tmp/nvim.tar.gz && \
    tar -xzvf /tmp/nvim.tar.gz -C /tmp && \
    cp -r /tmp/nvim-linux64/* /usr/local
COPY files/vim /tmp/vim/
RUN mkdir -p .config/nvim && \
    git clone --depth 1 https://github.com/wbthomason/packer.nvim\
 ~/.local/share/nvim/site/pack/packer/start/packer.nvim && \
    python3 -m pip install --user neovim pyright && \
    cp /tmp/vim/* -r .config/nvim/ && \
    nvim --headless -c 'q' && \
    ln -s /usr/local/bin/nvim /usr/local/bin/vim

# ----- RE Tools ----- #

RUN python3 -m pip install --user pwntools && \
    python3 -m pip install --user ptrlib && \
    python3 -m pip install --user ropper && \
    python3 -m pip install --user ROPGadget && \
    python3 -m pip install --user sagemath numpy

# Downgrade unicorn package to prevent pwntools crash
RUN pip3 install unicorn==1.0.3

# qemu
RUN mkdir -p /etc/qemu-binfmt && \ 
    ln -s /usr/arm-linux-gnueabi /etc/qemu-binfmt/arm

# gdb 
RUN mkdir -p /etc/debuginfod/ && \
    echo "https://debuginfod.elfutils.org/" >> urls.urls

# pwndbg
RUN git clone https://github.com/pwndbg/pwndbg
RUN cd ${HOME}/pwndbg && bash setup.sh && \
    echo "source ~/pwndbg/gdbinit.py" > ~/.gdbinit_pwndbg

# gef
COPY files/gdb /tmp/gdb
RUN apt update && apt install -y file git binutils vim gcc gdb python-is-python3 && \
    sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    dpkg-reconfigure --frontend=noninteractive locales && \
    update-locale LANG=en_US.UTF-8 && \
    bash -c "$(curl -fsSL https://gef.blah.cat/sh)" && \
    wget https://github.com/hugsy/gef/raw/main/scripts/gef-extras.sh && \
    sed -i -e "s/git clone/git clone -b 'fix_heap_viz_new_api'/g" gef-extras.sh && \
    chmod 755 gef-extras.sh && \
    ./gef-extras.sh && rm ./gef-extras.sh && \
    mv .gef-*.py .gdbinit_gef.py && \
    cp /tmp/gdb/.gdbinit /root/.gdbinit

WORKDIR /usr/bin
RUN cp /tmp/gdb/gdb-* . && \
    chmod +x /usr/bin/gdb-*

# Ruby Tools
RUN gem install seccomp-tools one_gadget

# xgadget
RUN cargo install xgadget --features cli-bin && \
    cargo install ripgrep

# pwn templates
COPY files/templates /tmp/templates
RUN mkdir /root/ctf-tools
RUN cp -r /tmp/templates /root/ctf-tools && \
    mv /root/ctf-tools/templates/make* /usr/bin && \
    chmod +x /usr/bin/makePWN* /root/ctf-tools/templates/*

# reutils
WORKDIR /root/ctf-tools
RUN python3 -m pip install click leaf && \
    git clone https://github.com/Ayrx/reutils.git

# libc database from heaplab
COPY files/libc-database /tmp/libc-database
RUN mv /tmp/libc-database /root/ctf-tools

# main arena offset
WORKDIR /root/ctf-tools
RUN git clone https://github.com/bash-c/main_arena_offset

# CTFmate
WORKDIR /root/ctf-tools
RUN git clone https://github.com/X3eRo0/CTFMate.git
WORKDIR /root/ctf-tools/CTFMate
RUN python3 -m pip install -r requirements.txt && \
    chmod +x /root/ctf-tools/CTFMate/ctfmate.py && \
    ln -s /root/ctf-tools/CTFMate/ctfmate.py /usr/bin/ctfmate

# pwninit
WORKDIR /usr/bin
RUN wget https://github.com/io12/pwninit/releases/download/3.2.0/pwninit && \
    chmod +x /usr/bin/pwninit

# extract ubuntu package
WORKDIR /usr/bin
COPY ./files/ubuntuGetLibc.sh /usr/bin/ubuntuGetLibc
RUN apt install -y zstd && \
    chmod +x /usr/bin/ubuntuGetLibc

# Kernel Stuff
WORKDIR /usr/bin
COPY ./files/decompressCPIO.sh /usr/bin/decompressCPIO
RUN wget -O extract-vmlinux https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux && \
    apt-get install cpio && \
    python3 -m pip install --upgrade git+https://github.com/marin-m/vmlinux-to-elf && \
    chmod +x /usr/bin/decompressCPIO && \
    chmod +x /usr/bin/extract-vmlinux

WORKDIR /root/data
RUN rm -rf /tmp/*
ENTRYPOINT [ "/usr/bin/zsh" ]

# vim: set syntax=dockerfile:
