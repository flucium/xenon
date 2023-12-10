FROM ubuntu:22.04
RUN apt update && apt upgrade -y &&\
apt install -y curl git build-essential pkg-config libssl-dev && \
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh && \
source "$HOME/.cargo/env" && \
rustup install nightly && rustup default nightly && \
mkdir workspace && cd workspace && \
git clone git@github.com:flucium/xenon.git && \
ls
