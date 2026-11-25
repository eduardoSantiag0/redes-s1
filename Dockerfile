FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    iproute2 \
    netcat-openbsd \
    iputils-ping \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

CMD ["sleep", "infinity"]