"""
Watchtower — web dashboard.

FastAPI backend over core.py (the same logic the terminal tool uses), serving
a small static HTML/JS/CSS frontend. No Node/npm build step -- this is
served as-is by FastAPI's StaticFiles, so there's nothing to compile.
"""
from __future__ import annotations

import os

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import core

app = FastAPI(title="Watchtower")

_client = None


def client():
    global _client
    if _client is None:
        _client = core.docker_client()
    else:
        try:
            _client.ping()
        except Exception:
            _client = core.docker_client()
    return _client


def _wrap(fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except core.NotFoundError as e:
        raise HTTPException(404, str(e))
    except ValueError as e:
        raise HTTPException(400, str(e))
    except FileNotFoundError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(500, str(e))
    except OSError as e:
        raise HTTPException(502, str(e))
    except Exception as e:
        raise HTTPException(500, f"{type(e).__name__}: {e}")


# ─── Diagnostics ────────────────────────────────────────────────────────────

@app.get("/api/status")
def api_status():
    return _wrap(core.stack_status, client())


@app.get("/api/resources")
def api_resources():
    return _wrap(core.container_resources, client())


@app.get("/api/tls")
def api_tls():
    return _wrap(core.tls_certs, client())


@app.get("/api/dns")
def api_dns():
    return _wrap(core.dns_resolution, client())


@app.get("/api/volume")
def api_volume():
    return _wrap(core.volume_disk)


@app.get("/api/environment/summary")
def api_environment_summary():
    return _wrap(core.environment_summary)


# ─── Tools ──────────────────────────────────────────────────────────────────

@app.get("/api/logs/{label}")
def api_logs(label: str, lines: int = 50):
    return {"text": _wrap(core.logs_tail, client(), label, lines)}


@app.post("/api/restart/{label}")
def api_restart(label: str):
    _wrap(core.restart_container, client(), label)
    return {"ok": True}


@app.get("/api/sources")
def api_sources():
    return _wrap(core.sources_destinations, client())


@app.get("/api/connectivity")
def api_connectivity():
    return _wrap(core.proxy_connectivity, client())


@app.get("/api/ports")
def api_ports():
    return _wrap(core.source_ports, client())


@app.get("/api/syslog/stats")
def api_syslog_stats():
    return _wrap(core.syslog_stats)


@app.post("/api/syslog/test")
def api_syslog_test():
    return _wrap(core.syslog_test)


# ─── Scenarios ──────────────────────────────────────────────────────────────

@app.get("/api/scenarios")
def api_scenarios():
    return _wrap(core.list_scenarios, client())


@app.get("/api/categories")
def api_categories():
    return core.CATEGORY_LABELS


class FireScenarioRequest(BaseModel):
    name: str = ""


@app.post("/api/fire/scenario")
def api_fire_scenario(body: FireScenarioRequest):
    return {"output": _wrap(core.fire_scenario, client(), body.name)}


class FireCategoryRequest(BaseModel):
    category: str


@app.post("/api/fire/category")
def api_fire_category(body: FireCategoryRequest):
    return {"output": _wrap(core.fire_category, client(), body.category)}


@app.post("/api/fire/sources")
def api_fire_sources():
    return {"output": _wrap(core.fire_sources, client())}


# ─── Environments ───────────────────────────────────────────────────────────

@app.get("/api/environments")
def api_list_environments():
    return _wrap(core.list_environments)


class AddEnvironmentRequest(BaseModel):
    name: str
    HEC_URL: str = ""
    HEC_TOKEN: str = ""
    HEC_INDEX: str = ""
    SDL_BASE_URL: str = ""
    SDL_READ_TOKEN: str = ""
    SDL_WRITE_TOKEN: str = ""
    SDL_ACCOUNT_ID: str = ""


@app.post("/api/environments")
def api_add_environment(body: AddEnvironmentRequest):
    fields = body.model_dump(exclude={"name"})
    _wrap(core.add_environment, body.name, fields)
    return {"ok": True}


class UpdateEnvironmentRequest(BaseModel):
    HEC_URL: str = ""
    HEC_TOKEN: str = ""
    HEC_INDEX: str = ""
    SDL_BASE_URL: str = ""
    SDL_READ_TOKEN: str = ""
    SDL_WRITE_TOKEN: str = ""
    SDL_ACCOUNT_ID: str = ""


@app.put("/api/environments/{name}")
def api_update_environment(name: str, body: UpdateEnvironmentRequest):
    _wrap(core.update_environment, name, body.model_dump())
    return {"ok": True}


class CaptureEnvironmentRequest(BaseModel):
    name: str = ""


@app.post("/api/environments/capture")
def api_capture_environment(body: CaptureEnvironmentRequest):
    name = _wrap(core.capture_current, body.name or None)
    return {"ok": True, "name": name}


@app.post("/api/environments/{name}/apply")
def api_apply_environment(name: str):
    return _wrap(core.apply_environment, name)


@app.delete("/api/environments/{name}")
def api_delete_environment(name: str):
    _wrap(core.delete_environment, name)
    return {"ok": True}


# ─── Static frontend (must be mounted last -- catches everything else) ─────

_static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/", StaticFiles(directory=_static_dir, html=True), name="static")
