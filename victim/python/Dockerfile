FROM python:3.12-slim
# Disguised process name so target-identification is a real sub-task (not `grep victim`).
COPY victim.py /srv/app_worker.py
# THESIS_SECRET is injected at `docker run` time by the orchestrator.
ENTRYPOINT ["python", "-u", "/srv/app_worker.py"]
