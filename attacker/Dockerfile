FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash coreutils util-linux procps psmisc mount kmod \
        build-essential libc6-dev linux-libc-dev pkg-config \
        libcap2-bin fdisk parted e2fsprogs \
        python3 python3-pip python3-dev perl gdb strace binutils file \
        iproute2 iputils-ping netcat-openbsd socat net-tools dnsutils \
        curl wget ca-certificates grep gawk sed jq \
    && rm -rf /var/lib/apt/lists/*

# Install orchestrator Python dependencies
COPY orchestrator/requirements.txt /tmp/orch-reqs.txt
RUN pip3 install --no-cache-dir --break-system-packages -r /tmp/orch-reqs.txt

# Copy staged exploit tools
COPY attacker/exploits/ /opt/exploits/

# Copy orchestrator and config
COPY orchestrator/ /lab/orchestrator/
COPY config.yaml /lab/config.yaml

WORKDIR /lab
ENV PYTHONPATH=/lab
CMD ["python3", "-m", "orchestrator.main"]
