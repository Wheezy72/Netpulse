import { defineStore } from "pinia";
import { ref, computed } from "vue";
import axios from "axios";

import { DEFAULT_AVATAR_STYLE, normalizeAvatarStyle } from "../utils/avatar";

/** Two roles: admin acts, viewer observes. */
type Role = "admin" | "viewer";

interface CurrentUser {
  id: number;
  /** The sign-in name. Accounts are created with a username and may have no
   *  email at all, so this is the only identifier always present. */
  username: string;
  email: string | null;
  full_name: string | null;
  role: Role;
  force_password_change: boolean;
}

/**
 * "A session is probably open." Not a credential: the session itself is an
 * HttpOnly cookie the page cannot read, so the worst a script can do with this
 * flag is make the app ask /api/auth/me and be told 401.
 *
 * It exists because the cookie is invisible to JavaScript, so the app would
 * otherwise have no way to decide between "try to restore the session" and
 * "show the sign-in screen" before the first request completes.
 */
const SESSION_HINT = "np-session";

export const useAuthStore = defineStore("auth", () => {
  const sessionHint = ref<boolean>(localStorage.getItem(SESSION_HINT) === "1");
  const user = ref<CurrentUser | null>(null);

  // The portrait skin is per account. It lives on the server (so the admin
  // roster renders every account in its own skin) and is mirrored into
  // localStorage so the avatar still renders before the fetch returns or while
  // the API is briefly unreachable.
  const avatarStyle = ref(DEFAULT_AVATAR_STYLE);

  function readAvatarStyle(username: string): string {
    return normalizeAvatarStyle(localStorage.getItem(`np-avatar-style:${username}`));
  }

  function setAvatarStyle(styleId: string): void {
    const valid = normalizeAvatarStyle(styleId);
    avatarStyle.value = valid;
    if (user.value?.username) {
      localStorage.setItem(`np-avatar-style:${user.value.username}`, valid);
    }
    // Fire-and-forget: a failed save must not roll the picker back — the UI
    // shows a working choice either way, and the next sign-in re-syncs.
    void axios.put("/api/settings/avatar-style", { style: valid }).catch(() => {});
  }

  const isAuthenticated = computed(() => sessionHint.value);
  const isAdmin = computed(() => user.value?.role === "admin");

  /**
   * Record that a session exists (or no longer does).
   *
   * The token string is accepted and ignored: older builds stored it in
   * localStorage and every call site still passes one. Nothing is written to
   * storage except the boolean hint — a credential must never be reachable
   * from JavaScript again.
   */
  function setToken(t: string | null, _persist = true) {
    sessionHint.value = !!t;
    if (t) {
      localStorage.setItem(SESSION_HINT, "1");
    } else {
      localStorage.removeItem(SESSION_HINT);
      // Clear tokens left behind by a previous build, which an injected script
      // could still read on an upgraded install.
      localStorage.removeItem("np-token");
      sessionStorage.removeItem("np-token");
      delete axios.defaults.headers.common["Authorization"];
      user.value = null;
      avatarStyle.value = DEFAULT_AVATAR_STYLE;
    }
  }

  /**
   * Resolve the signed-in account from the session cookie.
   *
   * Returns false when the API rejected the session (expired or revoked) and
   * the hint has been cleared — the router uses that to explain why sign-in is
   * being asked for again instead of silently bouncing to the form.
   */
  async function loadUser(): Promise<boolean> {
    if (!sessionHint.value) return false;
    try {
      const { data } = await axios.get<CurrentUser>("/api/auth/me");
      user.value = data;
      // The server copy is authoritative; the local one only covers the
      // request failing (API briefly down) or an account that never saved.
      let serverStyle: string | null = null;
      try {
        serverStyle = (await axios.get<{ avatar_style: string }>(
          "/api/settings/avatar-style"
        )).data.avatar_style;
      } catch {
        serverStyle = null;
      }
      avatarStyle.value = serverStyle ? normalizeAvatarStyle(serverStyle) : readAvatarStyle(data.username);
      return true;
    } catch {
      setToken(null);
      return false;
    }
  }

  async function logout() {
    try {
      if (sessionHint.value) {
        await axios.post("/api/auth/logout");
      }
    } catch (e) {
      console.error("Logout failed on backend:", e);
    } finally {
      setToken(null);
    }
  }

  return {
    user,
    avatarStyle,
    isAuthenticated,
    isAdmin,
    setToken,
    setAvatarStyle,
    loadUser,
    logout,
  };
});
