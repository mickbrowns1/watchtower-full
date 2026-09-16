# Pull just the docker CLI binary (no daemon) for the interactive
# "Service debugger" shell (docker exec -it ... sh) and any ad-hoc
# docker commands -- avoids adding a full apt docker.io dependency chain.
# Also grabs the bundled compose-v2 plugin, needed by the Environments tool
# to rewrite .env and recreate services with new SDL/HEC values applied.
FROM docker:cli AS dockercli

FROM python:3.12-slim
WORKDIR /app

COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=dockercli /usr/local/libexec/docker/cli-plugins/docker-compose /usr/local/libexec/docker/cli-plugins/docker-compose

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY core.py web.py watchtower.py ./
COPY static/ ./static/

EXPOSE 8000

# The container's main process serves the web dashboard (core.py's logic,
# same as the terminal tool below) -- see docker-compose.yml for the
# published port. The terminal tool is still available on demand, as a
# second independent session:
#   docker exec -it nexus-watchtower python3 watchtower.py
CMD ["python3", "-m", "uvicorn", "web:app", "--host", "0.0.0.0", "--port", "8000"]
