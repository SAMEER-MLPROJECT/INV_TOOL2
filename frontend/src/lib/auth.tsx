import { createContext, useCallback, useContext, useEffect, useState, type ReactNode } from "react";
import { api, ApiError, UNAUTHORIZED_EVENT } from "./api";
import type { Me } from "./types";

interface AuthState {
  me: Me | null;
  checked: boolean;
  refresh: () => Promise<void>;
  logout: () => Promise<void>;
  can: (p: keyof Me["permissions"]) => boolean;
}

const AuthCtx = createContext<AuthState>({ me: null, checked: false, refresh: async () => {}, logout: async () => {}, can: () => false });
export const useAuth = () => useContext(AuthCtx);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [me, setMe] = useState<Me | null>(null);
  const [checked, setChecked] = useState(false);
  const refresh = useCallback(async () => {
    try {
      setMe(await api.me());
    } catch (e) {
      if (!(e instanceof ApiError) || e.status === 401) setMe(null);
    } finally {
      setChecked(true);
    }
  }, []);
  const logout = useCallback(async () => {
    try { await api.logout(); } finally { setMe(null); window.location.hash = "/overview"; }
  }, []);
  useEffect(() => {
    refresh();
    const onUnauth = () => setMe(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauth);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauth);
  }, [refresh]);
  const can = useCallback((p: keyof Me["permissions"]) => !!me?.permissions[p], [me]);
  return <AuthCtx.Provider value={{ me, checked, refresh, logout, can }}>{children}</AuthCtx.Provider>;
}

export const ROLE_LABEL: Record<string, string> = { analyst: "SOC analyst", itadmin: "IT infrastructure admin", viewer: "Viewer (read-only)" };
