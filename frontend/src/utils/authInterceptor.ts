import axios from "axios";
import type { Pinia } from "pinia";
import type { Router } from "vue-router";

/** Endpoints that answer 401 for their own reasons (bad credentials). */
const CREDENTIAL_ENDPOINTS = ["/api/auth/login", "/api/auth/logout"];

/**
 * Send the operator back to the sign-in screen when the token stops being
 * valid, instead of leaving every panel showing "Failed to load …".
 *
 * This matters most for "Remember me" left unchecked: that token lives 60
 * minutes, so a long session hits it while still working. Without a handler the
 * router guard still believes the session is valid and nothing recovers until a
 * manual reload.
 */
export function installAuthInterceptor(router: Router, pinia: Pinia): void {
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

      // No token means an unauthenticated probe (setup status, health) or a
      // rejection the router guard already handled on boot — either way there
      // is nothing to announce from here.
      if (!auth.token) {
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
