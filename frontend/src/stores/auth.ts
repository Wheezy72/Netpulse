import { defineStore } from "pinia";
import { ref, computed } from "vue";
import axios from "axios";

import { DEFAULT_AVATAR_STYLE, normalizeAvatarStyle } from "../utils/avatar";
import { getStoredToken } from "../utils/token";

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

export const useAuthStore = defineStore("auth", () => {
  // Prefer a long-lived token from localStorage; fall back to a session-only
  // token stored in sessionStorage (used when "Remember me" is unchecked).
  const token = ref<string | null>(getStoredToken() || null);
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

  const isAuthenticated = computed(() => !!token.value);
  const isAdmin = computed(() => user.value?.role === "admin");

  /**
   * Store `t` and set the Axios Authorization header.
   * When `persist` is true (the default) the token survives browser restarts
   * via localStorage.  When false it is kept only for the current browser
   * session via sessionStorage — matching the "Remember me" checkbox intent.
   */
  function setToken(t: string | null, persist = true) {
    token.value = t;
    if (t) {
      if (persist) {
        localStorage.setItem("np-token", t);
        sessionStorage.removeItem("np-token");
      } else {
        sessionStorage.setItem("np-token", t);
        localStorage.removeItem("np-token");
      }
      axios.defaults.headers.common["Authorization"] = `Bearer ${t}`;
    } else {
      localStorage.removeItem("np-token");
      sessionStorage.removeItem("np-token");
      delete axios.defaults.headers.common["Authorization"];
      user.value = null;
      avatarStyle.value = DEFAULT_AVATAR_STYLE;
    }
  }

  /**
   * Resolve the signed-in account from the stored token.
   *
   * Returns false when the token was rejected (expired or revoked) and it has
   * been cleared — the router uses that to explain why sign-in is being asked
   * for again instead of silently bouncing to the form.
   */
  async function loadUser(): Promise<boolean> {
    if (!token.value) return false;
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
      if (token.value) {
        await axios.post("/api/auth/logout");
      }
    } catch (e) {
      console.error("Logout failed on backend:", e);
    } finally {
      setToken(null);
    }
  }

  // Restore token on app init.
  if (token.value) {
    axios.defaults.headers.common["Authorization"] = `Bearer ${token.value}`;
  }

  return { token, user, avatarStyle, isAuthenticated, isAdmin, setToken, setAvatarStyle, loadUser, logout };
});
