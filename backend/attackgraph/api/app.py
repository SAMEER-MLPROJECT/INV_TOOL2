from __future__ import annotations

import asyncio
import json
import logging
import os
import uuid
from datetime import datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from .. import __version__
from ..auth import CAN_INGEST, CAN_INVESTIGATE, CAN_MANAGE, ROLES, AuthError, AuthStore, User, bootstrap_demo, provision_devices
from ..config import AnalysisSettings, DeploymentConfig
from ..containment import WhatIfError
from ..edge import LED_LEVEL, to_records, verify_envelope
from ..evidence import explain_entity, explain_event, explain_relationship
from ..graph.blast import BlastError
from ..graph.paths import PathError, PathQuery
from ..ingest.loader import IngestError
from ..ingest.normalize import NormalizationError, parse_timestamp
from ..ingest.sources import ADAPTERS
from ..models import TRAVERSABLE, RelType
from ..orgs import OrgRegistry
from ..rules import RULES
from ..workspace import PersistenceUnavailable, Workspace

log = logging.getLogger("attackgraph.api")
MAX_FILES_PER_UPLOAD = 12
MAX_GRAPH_NODES = 600


class PathRequest(BaseModel):
    source: str
    targets: list[str] | None = None
    max_hops: int = Field(default=5, ge=1, le=8)
    max_paths: int = Field(default=12, ge=1, le=100)
    rel_types: list[RelType] | None = None
    since: str | None = None


class WhatIfRequest(BaseModel):
    source: str
    actions: list[str] = Field(min_length=1, max_length=8)
    at: str | None = None
    hops: int = Field(default=5, ge=1, le=8)


class StreamBatch(BaseModel):
    source_type: str | None = None
    records: list[dict[str, Any]] = Field(min_length=1, max_length=5000)


class ReplayRequest(BaseModel):
    start: str | None = None
    end: str | None = None
    speed: float = Field(default=120.0, ge=1, le=100_000)


class StatusRequest(BaseModel):
    status: str | None = None


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=60)
    password: str = Field(min_length=1, max_length=200)


class SignupRequest(BaseModel):
    organisation: str = Field(min_length=2, max_length=60)
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=1, max_length=200)
    load_sample: bool = True


class NewUserRequest(BaseModel):
    username: str = Field(min_length=3, max_length=40)
    password: str = Field(min_length=1, max_length=200)
    role: str


class NewDeviceRequest(BaseModel):
    name: str = Field(min_length=2, max_length=40)
    location: str = Field(min_length=2, max_length=60)


COOKIE = "agl_session"
CSRF_HEADER = "x-requested-with"


def _ts(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return parse_timestamp(value)[0]
    except NormalizationError as exc:
        raise HTTPException(422, f"invalid time: {exc}") from exc


def _current_user(request: Request) -> User | None:
    st = request.app.state
    if st.open_mode:
        return None
    user = st.store.user_for_token(request.cookies.get(COOKIE))
    if user is None:
        raise HTTPException(401, "sign in required")
    return user


def _ws_for(allowed: set[str] | None):
    def dep(request: Request) -> Workspace:
        st = request.app.state
        if st.open_mode:
            return st.ws
        user = _current_user(request)
        if allowed is not None and user.role not in allowed:
            raise HTTPException(403, f"your role ({user.role}) cannot do this")
        request.state.user = user
        return st.registry.get(user.org_id)
    return dep


RW = Annotated[Workspace, Depends(_ws_for(None))]
IW = Annotated[Workspace, Depends(_ws_for(CAN_INGEST))]
VW = Annotated[Workspace, Depends(_ws_for(CAN_INVESTIGATE))]
MW = Annotated[Workspace, Depends(_ws_for(CAN_MANAGE))]


def create_app(ws: Workspace | None = None, load_sample: bool = True, store: AuthStore | None = None,
               deploy: DeploymentConfig | None = None) -> FastAPI:
    open_mode = ws is not None and store is None
    deploy = ws.deploy if ws is not None else (deploy or DeploymentConfig())
    registry: OrgRegistry | None = None
    if open_mode:
        ws.open(load_sample=load_sample)
    else:
        store = store or AuthStore(deploy.auth_db, deploy.max_orgs)
        registry = OrgRegistry(deploy, store)
        if deploy.demo_password:
            try:
                created = bootstrap_demo(store, deploy.demo_password)
            except AuthError as exc:
                created = []
                log.error("evaluator accounts not set up: %s", exc)
            if created:
                log.info("created demo organisations and accounts: %s", ", ".join(a["username"] for a in created))
            log.info("evaluator accounts use the current AGL_DEMO_PASSWORD")
        elif not store.org_count():
            log.warning("no organisations yet: sign up in the UI, or set AGL_DEMO_PASSWORD to create demo accounts")
        if deploy.edge_devices:
            added = provision_devices(store, deploy.edge_devices)
            if added:
                log.info("provisioned edge devices from AGL_EDGE_DEVICES: %s", ", ".join(added))

    docs = open_mode or os.environ.get("AGL_ENABLE_DOCS", "0") == "1"
    app = FastAPI(title="AttackGraph Lens API", version=__version__, docs_url="/api/docs" if docs else None,
                  redoc_url=None, openapi_url="/api/openapi.json" if docs else None)
    app.state.ws = ws
    app.state.store = store
    app.state.registry = registry
    app.state.open_mode = open_mode
    app.add_middleware(CORSMiddleware, allow_origins=deploy.cors_origins, allow_credentials=True,
                       allow_methods=["GET", "POST", "PUT", "DELETE"], allow_headers=["Content-Type", "X-Requested-With"])

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        if (not open_mode and request.method in {"POST", "PUT", "DELETE", "PATCH"} and request.url.path.startswith("/api/")
                and not request.url.path.startswith("/api/edge/")
                and request.headers.get(CSRF_HEADER, "").lower() != "agl"):
            return JSONResponse({"detail": "missing X-Requested-With: agl header"}, status_code=403)
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
        resp.headers.setdefault("X-XSS-Protection", "0")
        resp.headers.setdefault("Content-Security-Policy",
                                "default-src 'self'; img-src 'self' data:; font-src 'self' data:; style-src 'self' 'unsafe-inline'; "
                                "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
        if request.url.scheme == "https":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    @app.exception_handler(Exception)
    async def unhandled(request: Request, exc: Exception):
        ref = uuid.uuid4().hex[:8]
        log.error("unhandled error ref=%s path=%s type=%s", ref, request.url.path, type(exc).__name__)
        return JSONResponse({"detail": f"Internal error (reference {ref}). See server log."}, status_code=500)

    @app.exception_handler(PersistenceUnavailable)
    async def persistence_down(request: Request, exc: PersistenceUnavailable):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(AuthError)
    async def auth_error(request: Request, exc: AuthError):
        return JSONResponse({"detail": exc.message}, status_code=exc.status)

    current_user = _current_user

    def _secure(request: Request) -> bool:
        if deploy.cookie_secure in {"1", "true", "yes"}:
            return True
        if deploy.cookie_secure in {"0", "false", "no"}:
            return False
        return request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "") == "https"

    def _client(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _set_session(resp: JSONResponse, request: Request, token: str) -> None:
        resp.set_cookie(COOKIE, token, max_age=8 * 3600, httponly=True, samesite="strict", secure=_secure(request), path="/")

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "auth": "disabled (single-workspace mode)" if open_mode else "required"}

    @app.get("/api/auth/config")
    def auth_config() -> dict:
        demo = []
        if not open_mode and deploy.show_demo_logins and deploy.demo_password:
            demo = [{"username": "analyst", "role": "analyst", "org": "Demo NBFC (synthetic data)"},
                    {"username": "itadmin", "role": "itadmin", "org": "Demo NBFC (synthetic data)"},
                    {"username": "viewer", "role": "viewer", "org": "Demo NBFC (synthetic data)"},
                    {"username": "client-b", "role": "analyst", "org": "Second client (empty)"}]
        return {"auth_required": not open_mode, "signup": (not open_mode) and deploy.allow_signup, "roles": list(ROLES),
                "demo_accounts": demo, "demo_password": deploy.demo_password if demo else None}

    @app.post("/api/auth/login")
    def login(body: LoginRequest, request: Request) -> JSONResponse:
        if open_mode:
            raise HTTPException(409, "authentication is disabled in single-workspace mode")
        token = store.authenticate(body.username, body.password, _client(request))
        user = store.user_for_token(token)
        resp = JSONResponse(user.public())
        _set_session(resp, request, token)
        return resp

    @app.post("/api/auth/signup")
    def signup(body: SignupRequest, request: Request) -> JSONResponse:
        if open_mode or not deploy.allow_signup:
            raise HTTPException(403, "sign-up is disabled on this deployment")
        if not store.signup_limiter.hit(f"signup:{_client(request)}"):
            raise HTTPException(429, "too many sign-ups from this address; try later")
        org_id = store.create_org(body.organisation, sample=body.load_sample)
        store.create_user(body.username, body.password, org_id, "analyst")
        token = store.authenticate(body.username, body.password, _client(request))
        resp = JSONResponse(store.user_for_token(token).public())
        _set_session(resp, request, token)
        return resp

    @app.post("/api/auth/logout")
    def logout(request: Request) -> JSONResponse:
        if not open_mode:
            store.logout(request.cookies.get(COOKIE))
        resp = JSONResponse({"status": "signed out"})
        resp.delete_cookie(COOKIE, path="/")
        return resp

    @app.get("/api/auth/me")
    def me(request: Request) -> dict:
        if open_mode:
            return {"username": "local", "role": "analyst", "org": {"id": "default", "name": "Local workspace"},
                    "permissions": {"ingest": True, "investigate": True, "manage": True}, "auth": False}
        return current_user(request).public() | {"auth": True}

    @app.get("/api/org/users")
    def org_users(request: Request, ws: RW) -> list[dict]:
        if open_mode:
            return []
        return store.users(current_user(request).org_id)

    @app.post("/api/org/users")
    def add_user(body: NewUserRequest, request: Request, ws: MW) -> dict:
        if open_mode:
            raise HTTPException(409, "user management needs authentication enabled")
        user = current_user(request)
        store.create_user(body.username, body.password, user.org_id, body.role)
        return {"username": body.username.strip().lower(), "role": body.role}

    @app.get("/api/org/devices")
    def org_devices(request: Request, ws: RW) -> list[dict]:
        if open_mode:
            return []
        return store.devices(current_user(request).org_id)

    @app.post("/api/org/devices")
    def add_device(body: NewDeviceRequest, request: Request, ws: MW) -> dict:
        if open_mode:
            raise HTTPException(409, "edge devices need authentication enabled")
        dev = store.create_device(current_user(request).org_id, body.name, body.location)
        return dev | {"note": "copy the secret now: it is shown only once"}

    @app.post("/api/edge/events")
    async def edge_events(request: Request) -> dict:
        if open_mode:
            raise HTTPException(409, "edge devices need authentication enabled")
        body = await request.body()
        dev, env, flags = verify_envelope(store, request.headers.get("x-agl-device", ""),
                                          request.headers.get("x-agl-signature", ""), body)
        target = registry.get(dev["org_id"])
        records = to_records(dev, env, flags)
        accepted = 0
        if records:
            try:
                res = target.live.ingest(records, "edge_physical")
            except IngestError as exc:
                raise HTTPException(422, str(exc)) from None
            accepted = res["accepted"]
            target.live.flush()
        incs = target.incidents
        top = incs[0]["priority"] if incs else "Low"
        return {"seq": env["seq"], "accepted": accepted, "flags": flags, "top_priority": top,
                "led_level": LED_LEVEL.get(top, 0), "open_incidents": len(incs)}

    @app.get("/api/summary")
    def summary(ws: RW) -> dict:
        return ws.summary()

    @app.get("/api/rules")
    def rules() -> dict:
        return RULES

    @app.get("/api/sources")
    def sources() -> list[dict]:
        return [{"name": a.name, "label": a.label, "required_fields": sorted(a.signature), "id_field": a.id_field,
                 "time_field": a.time_field, "context": a.is_context} for a in ADAPTERS]

    @app.get("/api/datasets")
    def datasets(ws: RW) -> dict:
        return {"files": ws.file_summaries(), "cross_file": dict(ws.cross_file)}

    @app.post("/api/datasets/sample")
    def reset_sample(ws: MW) -> dict:
        return {"files": ws.load_sample()}

    @app.post("/api/datasets/clear")
    def clear(ws: MW) -> dict:
        ws.reset()
        return {"status": "cleared"}

    @app.post("/api/datasets/upload")
    async def upload(ws: IW, files: list[UploadFile] = File(...), source_type: str = Form(""), mode: str = Form("append")) -> dict:
        if mode not in {"append", "replace"}:
            raise HTTPException(422, "mode must be append or replace")
        if len(files) > MAX_FILES_PER_UPLOAD:
            raise HTTPException(413, f"at most {MAX_FILES_PER_UPLOAD} files per upload")
        items = []
        for f in files:
            cap = (f.filename or "").lower().endswith((".pcap", ".pcapng", ".cap"))
            limit = ws.deploy.max_capture_bytes if cap else ws.deploy.max_upload_bytes
            data = await f.read(limit + 1)
            if len(data) > limit:
                raise HTTPException(413, f"{f.filename}: larger than {limit // (1024 * 1024)} MB")
            items.append((f.filename or "upload", data, source_type or None))
        if mode == "replace":
            ws.reset()
        return {"files": ws.ingest(items)}

    @app.get("/api/entities")
    def entities(ws: RW, type: str | None = None, q: str | None = None, limit: int = Query(500, ge=1, le=5000)) -> list[dict]:
        return ws.entity_list(type, q, limit)

    @app.get("/api/entities/{entity_id:path}")
    def entity(ws: RW, entity_id: str) -> dict:
        res = explain_entity(ws.graph, entity_id, ws.statuses)
        if res is None:
            raise HTTPException(404, "entity not found")
        res["incidents"] = [i["id"] for i in ws.incidents if any(entity_id in v for v in i["entities"].values())]
        return res

    @app.post("/api/entities/{entity_id:path}/status")
    def set_status(ws: VW, entity_id: str, body: StatusRequest, request: Request) -> dict:
        user = getattr(request.state, "user", None)
        try:
            ws.set_status(entity_id, body.status, by=user.username if user else "local")
        except KeyError:
            raise HTTPException(404, "entity not found") from None
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        return {"entity": entity_id, "status": body.status}

    @app.get("/api/relationships/{rel_id:path}")
    def relationship(ws: RW, rel_id: str) -> dict:
        res = explain_relationship(ws.graph, rel_id)
        if res is None:
            raise HTTPException(404, "relationship not found")
        uids = {o["event_uid"] for o in res["occurrences"]}
        res["incidents"] = [i["id"] for i in ws.incidents if uids & set(i["supporting_events"])]
        return res

    @app.get("/api/graph")
    def graph(ws: RW,
        types: str | None = None, rels: str | None = None, since: str | None = None, until: str | None = None,
        focus: str | None = None, depth: int = Query(1, ge=0, le=4), min_suspicion: float = Query(0.0, ge=0, le=1),
        include_context: bool = False, limit: int = Query(300, ge=1, le=MAX_GRAPH_NODES),
    ) -> dict:
        g = ws.graph
        t0, t1 = _ts(since), _ts(until)
        type_set = set(types.split(",")) if types else None
        try:
            rel_set = {RelType(r) for r in rels.split(",")} if rels else None
        except ValueError as exc:
            raise HTTPException(422, "unknown relationship type") from exc
        allowed_rels = rel_set or (set(RelType) if include_context else set(TRAVERSABLE))

        def rel_ok(r) -> bool:
            if r.type not in allowed_rels:
                return False
            occ = [o for o in r.occurrences if (t0 is None or o.timestamp >= t0) and (t1 is None or o.timestamp <= t1)]
            return bool(occ) and max(o.suspicion for o in occ) >= min_suspicion

        node_ok = lambda n: type_set is None or g.entities[n].type.value in type_set  # noqa: E731
        if focus:
            if focus not in g.entities:
                raise HTTPException(404, "focus entity not found")
            keep = {focus}
            frontier = {focus}
            for _ in range(depth):
                nxt = set()
                for n in frontier:
                    for u, v, d in list(g.g.out_edges(n, data=True)) + list(g.g.in_edges(n, data=True)):
                        if rel_ok(g.rels[d["rel_id"]]):
                            other = v if u == n else u
                            if node_ok(other) and other not in keep:
                                nxt.add(other)
                keep |= nxt
                frontier = nxt
                if len(keep) > limit:
                    break
        else:
            keep = {r.source for r in g.rels.values() if rel_ok(r)} | {r.target for r in g.rels.values() if rel_ok(r)}
            keep = {n for n in keep if node_ok(n)}
        truncated = len(keep) > limit
        if truncated:
            keep = set(sorted(keep, key=lambda n: (n != focus, -g.entities[n].criticality, -g.g.degree(n), n))[:limit])
        nodes = [{"id": n, "type": g.entities[n].type.value, "name": g.entities[n].name, "category": g.entities[n].category,
                  "criticality": g.entities[n].criticality, "in_inventory": g.entities[n].in_inventory,
                  "status": ws.statuses.get(n)} for n in sorted(keep)]
        edges = []
        for r in g.rels.values():
            if r.source in keep and r.target in keep and rel_ok(r):
                edges.append({"id": r.id, "source": r.source, "target": r.target, "type": r.type.value,
                              "count": len(r.occurrences), "basis": r.basis.value, "max_suspicion": round(r.max_suspicion, 3),
                              "first_seen": r.first_seen.isoformat(), "last_seen": r.last_seen.isoformat()})
        return {"nodes": nodes, "edges": edges, "truncated": truncated, "limit": limit}

    @app.post("/api/paths")
    def paths(ws: RW, req: PathRequest) -> dict:
        q = PathQuery(source=req.source, targets=req.targets or None, max_hops=req.max_hops, max_paths=req.max_paths,
                      rel_types=set(req.rel_types) if req.rel_types else None, since=_ts(req.since))
        try:
            return ws.paths(q)
        except PathError as exc:
            raise HTTPException(422, str(exc)) from exc

    @app.get("/api/blast-radius/{entity_id:path}")
    def blast(ws: RW, entity_id: str, hops: int = Query(3, ge=1, le=8), temporal: bool = True, since: str | None = None,
              include_processes: bool = True) -> dict:
        try:
            return ws.blast(entity_id, hops, temporal, _ts(since), include_processes)
        except BlastError as exc:
            raise HTTPException(404 if "unknown" in str(exc) else 422, str(exc)) from exc

    @app.get("/api/incidents")
    def incidents(ws: RW) -> list[dict]:
        keys = ("id", "title", "priority", "score", "start", "end", "identities", "affected_assets", "independent_sources",
                "evidence_sources", "dismissed_by_source")
        return [{k: i[k] for k in keys} | {"alerts": len(i["alerts"]), "seeds": len(i["seed_events"]),
                                           "supporting_events": len(i["supporting_events"])} for i in ws.incidents]

    @app.get("/api/incidents/{inc_id}")
    def incident(ws: RW, inc_id: str, request: Request) -> dict:
        user = getattr(request.state, "user", None)
        if ws.incident(inc_id) is not None:
            ws.mark_opened(inc_id, user.username if user else "local")
        inc = ws.incident_detail(inc_id)
        if inc is None:
            raise HTTPException(404, "incident not found")
        return inc

    @app.get("/api/incidents/{inc_id}/containment")
    def containment(ws: RW, inc_id: str, at: str | None = None, hops: int = Query(5, ge=1, le=8)) -> dict:
        try:
            return ws.containment(inc_id, _ts(at), hops)
        except KeyError:
            raise HTTPException(404, "incident not found") from None
        except (ValueError, WhatIfError) as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/incidents/{inc_id}/hypotheses")
    def hypotheses(ws: RW, inc_id: str) -> dict:
        try:
            return ws.hypotheses(inc_id)
        except KeyError:
            raise HTTPException(404, "incident not found") from None

    @app.post("/api/datasets/real")
    def load_real(ws: MW) -> dict:
        files = ws.load_real()
        return {"files": files, "dataset": "OTRF Security-Datasets LSASS_campaign_03 (real recorded attack, MIT licence)"}

    @app.get("/api/incidents/{inc_id}/regulatory")
    def regulatory(ws: RW, inc_id: str, request: Request) -> dict:
        user = getattr(request.state, "user", None)
        try:
            return ws.regulatory(inc_id, user.org_name if user else "Local workspace")
        except KeyError:
            raise HTTPException(404, "incident not found") from None

    @app.get("/api/incidents/{inc_id}/admin")
    def admin_overview(ws: RW, inc_id: str) -> dict:
        try:
            return ws.admin_overview(inc_id)
        except KeyError:
            raise HTTPException(404, "incident not found") from None

    @app.post("/api/whatif")
    def whatif(ws: RW, req: WhatIfRequest) -> dict:
        try:
            return ws.what_if(req.source, req.actions, _ts(req.at), req.hops)
        except (WhatIfError, PathError, BlastError) as exc:
            raise HTTPException(422, str(exc)) from None

    @app.get("/api/deviations")
    def deviations(ws: RW, limit: int = Query(50, ge=1, le=500)) -> dict:
        return ws.deviations(limit)

    @app.get("/api/incidents/{inc_id}/report")
    def report(ws: RW, inc_id: str, request: Request, format: str = Query("html", pattern="^(json|md|html)$")) -> Response:
        user = getattr(request.state, "user", None)
        try:
            name, body, mime = ws.export_incident(inc_id, format, user.org_name if user else "Local workspace")
        except KeyError:
            raise HTTPException(404, "incident not found") from None
        return Response(body, media_type=mime, headers={"Content-Disposition": f'attachment; filename="{name}"'})

    @app.post("/api/stream/events")
    def stream_events(ws: IW, batch: StreamBatch, request: Request) -> dict:
        if int(request.headers.get("content-length") or 0) > ws.deploy.max_upload_bytes:
            raise HTTPException(413, "batch too large")
        try:
            return ws.live.ingest(batch.records, batch.source_type)
        except IngestError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/stream/flush")
    def stream_flush(ws: IW) -> dict:
        ws.live.flush()
        return ws.live.status()

    @app.get("/api/stream/status")
    def stream_status(ws: RW) -> dict:
        return ws.live.status()

    @app.post("/api/stream/replay")
    def stream_replay(ws: IW, req: ReplayRequest) -> dict:
        try:
            return ws.live.start_replay(_ts(req.start), _ts(req.end), req.speed)
        except IngestError as exc:
            raise HTTPException(409, str(exc)) from None

    @app.post("/api/stream/replay/stop")
    def stream_replay_stop(ws: IW) -> dict:
        return ws.live.stop_replay()

    @app.get("/api/stream/updates")
    async def stream_updates(ws: RW, request: Request, max_updates: int = Query(0, ge=0, le=10_000)):
        async def gen():
            last, sent, idle = -1, 0, 0.0
            while True:
                if await request.is_disconnected():
                    break
                if ws.live.version != last:
                    last = ws.live.version
                    payload = json.dumps(ws.live.last_update or {"version": last})
                    yield f"event: update\ndata: {payload}\n\n"
                    sent += 1
                    idle = 0.0
                    if max_updates and sent >= max_updates:
                        break
                elif idle >= 15:
                    yield ": keep-alive\n\n"
                    idle = 0.0
                await asyncio.sleep(0.25)
                idle += 0.25
        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/events")
    def events(ws: RW, q: str | None = None, source: str | None = None, category: str | None = None, entity: str | None = None,
               min_severity: float = Query(0.0, ge=0, le=1), offset: int = Query(0, ge=0), limit: int = Query(100, ge=1, le=1000)) -> dict:
        g = ws.graph
        pool = (g.events[u] for u in g.entity_events.get(entity, ())) if entity else g.events.values()
        from ..evidence import event_dict
        rows = []
        for ev in pool:
            if source and ev.source_system != source:
                continue
            if category and ev.category != category:
                continue
            if ev.severity < min_severity:
                continue
            d = event_dict(ev)
            if q and q.lower() not in (d["description"] + " " + ev.uid + " " + ev.source_file).lower():
                continue
            rows.append(d)
        rows.sort(key=lambda d: (d["timestamp"], d["uid"]))
        return {"total": len(rows), "offset": offset, "limit": limit, "events": rows[offset:offset + limit]}

    @app.get("/api/events/{uid:path}")
    def event(ws: RW, uid: str) -> dict:
        res = explain_event(ws.graph, uid)
        if res is None:
            raise HTTPException(404, "event not found")
        res["incidents"] = [i["id"] for i in ws.incidents if uid in i["supporting_events"]]
        return res

    @app.get("/api/evidence/manifest")
    def manifest(ws: RW, download: bool = False) -> Any:
        m = ws.manifest()
        if download:
            return Response(json.dumps(m, indent=2), media_type="application/json",
                            headers={"Content-Disposition": 'attachment; filename="evidence_manifest.json"'})
        return m

    @app.get("/api/settings")
    def get_settings(ws: RW) -> dict:
        return ws.settings.model_dump()

    @app.put("/api/settings")
    def put_settings(ws: MW, body: AnalysisSettings) -> dict:
        ws.update_settings(body)
        return ws.settings.model_dump()

    @app.post("/api/settings/reset")
    def reset_settings(ws: MW) -> dict:
        ws.update_settings(AnalysisSettings())
        return ws.settings.model_dump()

    @app.get("/api/backend")
    def backend(ws: RW) -> dict:
        return ws.backend_status()

    @app.get("/api/backend/neo4j/provenance/{entity_id:path}")
    def neo4j_provenance(ws: RW, entity_id: str, limit: int = Query(25, ge=1, le=200)) -> dict:
        if not (ws.persistent and ws.neo4j is not None and ws.neo4j_state.get("connected")):
            raise HTTPException(409, "Neo4j is not connected; provenance is shown from the in-memory engine instead")
        try:
            return {"entity": entity_id, "source": "neo4j", "records": ws.neo4j.entity_provenance(ws.org_id, entity_id, limit)}
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(503, f"Neo4j query failed ({type(exc).__name__})") from None

    @app.get("/api/backend/neo4j/counts")
    def neo4j_counts(ws: RW) -> dict:
        if not (ws.persistent and ws.neo4j is not None and ws.neo4j_state.get("connected")):
            raise HTTPException(409, "Neo4j is not connected")
        try:
            return ws.neo4j.counts(ws.org_id)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(503, f"Neo4j query failed ({type(exc).__name__})") from None

    @app.post("/api/backend/neo4j/sync")
    def neo4j_sync(ws: MW) -> dict:
        if not ws.deploy.neo4j_uri:
            raise HTTPException(409, "Neo4j is not configured. Set NEO4J_URI, NEO4J_USERNAME and NEO4J_PASSWORD and restart.")
        return ws.neo4j_connect_and_sync()

    @app.get("/.well-known/security.txt", include_in_schema=False)
    def security_txt() -> Response:
        contact = os.environ.get("AGL_SECURITY_CONTACT", "mailto:security@example.invalid")
        return Response(f"Contact: {contact}\nPreferred-Languages: en\nExpires: 2027-11-21T00:00:00.000Z\n",
                        media_type="text/plain")

    @app.get("/robots.txt", include_in_schema=False)
    def robots() -> Response:
        return Response("User-agent: *\nDisallow: /api/\n", media_type="text/plain")

    dist: Path = deploy.frontend_dist
    if (dist / "index.html").is_file():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        @app.get("/{full_path:path}", include_in_schema=False)
        def spa(full_path: str):
            if full_path.startswith("api/"):
                raise HTTPException(404, "not found")
            candidate = (dist / full_path).resolve()
            if full_path and candidate.is_file() and dist.resolve() in candidate.parents:
                return FileResponse(candidate)
            return FileResponse(dist / "index.html")
    else:
        @app.get("/", include_in_schema=False)
        def no_ui() -> dict:
            return {"message": "AttackGraph Lens API is running. Build the UI with `npm run build` in frontend/, "
                               "or open /api/docs for the API."}

    return app
