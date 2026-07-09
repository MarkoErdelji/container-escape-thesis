FROM gcc:13 AS build
WORKDIR /src
COPY victim.c .
RUN apt-get update && apt-get install -y libssl-dev && rm -rf /var/lib/apt/lists/*
RUN gcc -O0 -o victim_bin victim.c -lcrypto

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends libssl3 && rm -rf /var/lib/apt/lists/*
# Disguised process name so target-identification is a real sub-task (not `grep victim`).
COPY --from=build /src/victim_bin /usr/local/bin/app-worker
ENTRYPOINT ["/usr/local/bin/app-worker"]
