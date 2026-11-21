from __future__ import annotations

import threading

from .auth import AuthStore
from .config import AnalysisSettings, DeploymentConfig
from .workspace import Workspace


class OrgRegistry:
    """One isolated Workspace per organisation. Nothing is shared between organisations."""

    def __init__(self, deploy: DeploymentConfig, store: AuthStore) -> None:
        self.deploy = deploy
        self.store = store
        self._ws: dict[str, Workspace] = {}
        self._lock = threading.Lock()

    def get(self, org_id: str) -> Workspace:
        with self._lock:
            ws = self._ws.get(org_id)
            if ws is not None:
                return ws
            org = next((o for o in self.store.orgs() if o["id"] == org_id), None)
            if org is None:
                raise KeyError(org_id)
            ws = Workspace(self.deploy, AnalysisSettings(), org_id=org_id)
            self._ws[org_id] = ws
        ws.open(load_sample=org["sample"])
        return ws

    def loaded(self) -> dict[str, Workspace]:
        return dict(self._ws)
