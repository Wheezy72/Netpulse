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
  const token = ref<string | null>(localStorage.getItem("np-token"));
  const user = ref<CurrentUser | null>(null);

  const isAuthenticated = computed(() => !!token.value);
  const isAdmin = computed(() => user.value?.role === "admin");

  function setToken(t: string | null) {
    token.value = t;
    if (t) {
      localStorage.setItem("np-token", t);
      axios.defaults.headers.common["Authorization"] = `Bearer ${t}`;
    } else {
      localStorage.removeItem("np-token");
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
