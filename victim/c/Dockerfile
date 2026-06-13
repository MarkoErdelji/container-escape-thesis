# Build a static-ish C victim. Two-stage so the runtime image is tiny.
FROM gcc:13 AS build
WORKDIR /src
COPY victim.c .
RUN gcc -O0 -o victim_bin victim.c

FROM debian:bookworm-slim
# Disguised process name so target-identification is a real sub-task (not `grep victim`).
COPY --from=build /src/victim_bin /usr/local/bin/app-worker
# THESIS_SECRET is injected at `docker run` time by the orchestrator.
ENTRYPOINT ["/usr/local/bin/app-worker"]
