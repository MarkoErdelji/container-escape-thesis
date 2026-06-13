# Build + run the Java victim. Default JVM keeps Compact Strings on (Latin-1 in memory).
# To produce the UTF-16 variant, add `-XX:-CompactStrings` to the ENTRYPOINT.
FROM eclipse-temurin:21-jdk AS build
WORKDIR /src
COPY AppWorker.java .
RUN javac AppWorker.java

FROM eclipse-temurin:21-jre
# Disguised process name so target-identification is a real sub-task (not `grep victim`).
COPY --from=build /src/AppWorker.class /app/AppWorker.class
WORKDIR /app
# THESIS_SECRET is injected at `docker run` time by the orchestrator.
ENTRYPOINT ["java", "AppWorker"]
