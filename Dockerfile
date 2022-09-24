FROM ubuntu:20.04

# ----- Setup Enviornment ----- #
# get basics
USER root
ENV HOME /root
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
    python3\
    python3-pip\
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
    # connectivity
    sshpass\
    sshfs\
    socat\
    netcat\
    # qemu
    qemu-user\
    qemu-kvm

# Tooling
RUN apt-get update && \
    apt-get install -y\
    python3\
    python3-pip\
    ipython3\
    ruby\
    ruby-dev\
    # debugging
    libgmp-dev\
    texinfo\
    libc6-armel-cross\
    gdb-multiarch\
    gdb\
    # ctfmate
    patchelf\
    elfutils

# configure python(s)
RUN python3 -m pip install --upgrade setuptools
ENV PATH ${HOME}/.local/bin:${PATH}

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH ${HOME}/.cargo/bin:${PATH}

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
COPY files/tmux/.tmux.conf.local /tmp/.tmux.conf.local
RUN git clone https://github.com/gpakosz/.tmux.git && \
    ln -s -f .tmux/.tmux.conf && \
    cp /tmp/.tmux.conf.local ${HOME}

# setup vim to be awesome
RUN wget https://github.com/neovim/neovim/releases/download/v0.7.0/nvim-linux64.tar.gz -O /tmp/nvim.tar.gz && \
    tar -xzvf /tmp/nvim.tar.gz -C /tmp && \
    cp -r /tmp/nvim-linux64/* /usr/local
COPY files/vim /tmp/vim/
RUN mkdir -p .config/nvim && \
    git clone --depth 1 https://github.com/wbthomason/packer.nvim\
 ~/.local/share/nvim/site/pack/packer/start/packer.nvim && \
    python3 -m pip install --user neovim pyright && \
    cp /tmp/vim/* -r .config/nvim/ && \
    nvim --headless -u ~/.config/nvim/lua/plugins.lua -c 'autocmd User PackerComplete quitall' -c 'PackerSync' && \
    ln -s /usr/local/bin/nvim /usr/local/bin/vim

# ----- RE Tools ----- #

RUN python3 -m pip install --upgrade pip && \
    python3 -m pip install --user pwntools && \
    python3 -m pip install --user ropper && \
    python3 -m pip install --user ROPGadget && \
    python3 -m pip install --user sagemath numpy

# Downgrade unicorn package to prevent pwntools crash
RUN pip3 install unicorn==1.0.3

# ----- Build Tools ----- #
RUN pip3 install meson ninja

# # install gdb
# RUN cd /tmp && \
# wget https://sourceware.org/pub/gdb/snapshots/current/gdb-13.0.50.20220822.tar.xz -O gdb.tar.xz && \
# tar xf gdb.tar.xz && \
# cd gdb-13.0.50.20220822 && \
# ./configure && make -j8 && make install

#rizin
RUN git clone https://github.com/rizinorg/rizin && \
    cd rizin && \
    meson --buildtype=release build && \
    ninja -C build && \
    ninja -C build install

#rz-ghidra
RUN git clone https://github.com/rizinorg/rz-ghidra && \
    cd rz-ghidra && \
    git submodule init && \
    git submodule update && \
    mkdir build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=~/.local/ .. && \
    make && \
    make install

# pwndbg
RUN git clone https://github.com/pwndbg/pwndbg
RUN cd ${HOME}/pwndbg && bash setup.sh && \
    echo "source ~/pwndbg/gdbinit.py" > ~/.gdbinit_pwndbg

# peda
RUN git clone https://github.com/longld/peda.git ~/peda

# gef
COPY files/gdb /tmp/gdb
RUN python3 -m pip install rpyc keystone-engine && \
    wget -q -O ~/.gdbinit-gef.py https://gef.blah.cat/py && \
    echo source ~/.gdbinit-gef.py >> ~/.gdbinit && \
    wget -q -O- https://github.com/hugsy/gef/raw/main/scripts/gef-extras.sh | sh && \
    cp /tmp/gdb/.gdbinit /root/.gdbinit

WORKDIR /usr/bin
RUN cp /tmp/gdb/gdb-* . && \
    chmod +x /usr/bin/gdb-*

# heapinspect
WORKDIR /root/ctf-tools
RUN git clone https://github.com/matrix1001/heapinspect.git

# Ruby Tools
RUN gem install seccomp-tools one_gadget

# xgadget
RUN cargo install xgadget --features cli-bin

# pwn templates
COPY files/templates /tmp/templates
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
RUN wget -O extract-vmlinux https://raw.githubusercontent.com/torvalds/linux/master/scripts/extract-vmlinux && \
    python3 -m pip install --upgrade git+https://github.com/marin-m/vmlinux-to-elf

WORKDIR /root/data
RUN rm -rf /tmp/*
ENTRYPOINT [ "/usr/bin/zsh" ]

# vim: set syntax=dockerfile:
