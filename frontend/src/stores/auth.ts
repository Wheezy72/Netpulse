import { defineStore } from "pinia";
import { ref, computed } from "vue";
import axios from "axios";

type Role = "admin" | "operator";

interface CurrentUser {
  id: number;
  email: string;
  full_name: string | null;
  role: Role;
}

export const useAuthStore = defineStore("auth", () => {
  // Prefer a long-lived token from localStorage; fall back to a session-only
  // token stored in sessionStorage (used when "Remember me" is unchecked).
  const token = ref<string | null>(
    localStorage.getItem("np-token") ?? sessionStorage.getItem("np-token")
  );
  const user = ref<CurrentUser | null>(null);

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
    }
  }

  async function loadUser() {
    if (!token.value) return;
    try {
      const { data } = await axios.get<CurrentUser>("/api/auth/me");
      user.value = data;
    } catch {
      // Token may be expired – clear it.
      setToken(null);
    }
  }

  function logout() {
    setToken(null);
  }

  // Restore token on app init.
  if (token.value) {
    axios.defaults.headers.common["Authorization"] = `Bearer ${token.value}`;
  }

  return { token, user, isAuthenticated, isAdmin, setToken, loadUser, logout };
});
