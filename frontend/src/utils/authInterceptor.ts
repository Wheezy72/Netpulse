import axios from "axios";
import type { Pinia } from "pinia";
import type { Router } from "vue-router";

/** Endpoints that answer 401 for their own reasons (bad credentials). */
const CREDENTIAL_ENDPOINTS = [
  "/api/auth/login",
  "/api/auth/login/totp",
  "/api/auth/logout",
];

/** Methods the CSRF check applies to on the server. */
const UNSAFE_METHODS = new Set(["post", "put", "patch", "delete"]);

const CSRF_COOKIE = "np_csrf";
const CSRF_HEADER = "X-CSRF-Token";

function readCookie(name: string): string {
  const match = document.cookie.match(new RegExp(`(?:^|; )${name}=([^;]*)`));
  return match ? decodeURIComponent(match[1]) : "";
}

/**
 * Send the session cookie with every API call, and mirror the readable CSRF
 * cookie into a header for writes.
 *
 * The session token is never touched here: it is HttpOnly, so the browser
 * attaches it and JavaScript cannot read it. The CSRF cookie is readable by
 * design — that is what makes the double-submit check possible — and it is
 * useless on its own.
 */
export function installAuthInterceptor(router: Router, pinia: Pinia): void {
  axios.defaults.withCredentials = true;

  // Tokens stored by earlier builds are still readable by any injected script,
  // so an upgraded install clears them on load.
  localStorage.removeItem("np-token");
  sessionStorage.removeItem("np-token");
  delete axios.defaults.headers.common["Authorization"];

  axios.interceptors.request.use((config) => {
    const method = (config.method || "get").toLowerCase();
    if (UNSAFE_METHODS.has(method)) {
      const token = readCookie(CSRF_COOKIE);
      if (token) {
        config.headers = config.headers ?? {};
        (config.headers as Record<string, string>)[CSRF_HEADER] = token;
      }
    }
    return config;
  });

  axios.interceptors.response.use(
    (response) => response,
    async (error) => {
      const status = error?.response?.status;
      const url: string = error?.config?.url ?? "";

      if (status !== 401 || CREDENTIAL_ENDPOINTS.some((endpoint) => url.includes(endpoint))) {
        return Promise.reject(error);
      }

      const { useAuthStore } = await import("../stores/auth");
      const auth = useAuthStore(pinia);

      // No session means an unauthenticated probe (setup status, health) or a
      // rejection the router guard already handled on boot — either way there
      // is nothing to announce from here.
      if (!auth.isAuthenticated) {
        return Promise.reject(error);
      }
      auth.setToken(null);

      // The router guard often redirects to /login first (it also calls
      // /api/auth/me on load), so this must still add the notice to a login
      // page that is already on screen — otherwise the operator just sees the
      // sign-in form again with no explanation.
      const current = router.currentRoute.value;
      const onLogin = current.name === "login";
      if (!(onLogin && current.query.expired === "1")) {
        const redirect = onLogin
          ? (current.query.redirect as string | undefined)
          : current.fullPath;
        void router.replace({
          name: "login",
          query: { ...(redirect ? { redirect } : {}), expired: "1" },
        });
      }
      return Promise.reject(error);
    },
  );
}
