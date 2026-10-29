import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";

// The browser tab is part of the product: without a title per route it shows
// the bare path ("localhost/settings"), which reads like a debug server.
const APP_NAME = "NetPulse";

// All views are lazy-loaded so the initial bundle stays small.
const routes: RouteRecordRaw[] = [
  {
    path: "/",
    redirect: "/dashboard",
  },
  {
    path: "/dashboard",
    name: "dashboard",
    component: () => import("../views/Dashboard.vue"),
    meta: { requiresAuth: true, title: "Overview" },
  },
  {
    path: "/devices",
    name: "devices",
    component: () => import("../views/Devices.vue"),
    meta: { requiresAuth: true, title: "Devices" },
  },
  {
    path: "/topology",
    name: "topology",
    component: () => import("../views/InteractiveTopology.vue"),
    meta: { requiresAuth: true, title: "Topology" },
  },
  {
    path: "/toolbox",
    name: "toolbox",
    component: () => import("../views/Toolbox.vue"),
    meta: { requiresAuth: true, title: "Toolbox" },
  },
  {
    path: "/logs",
    name: "logs",
    component: () => import("../views/Logs.vue"),
    meta: { requiresAuth: true, title: "Logs" },
  },
  {
    // The offline "Backup Friend" assistant duplicated the device views —
    // removed. Old bookmarks land on the canonical inventory instead.
    path: "/offline-assistant",
    redirect: "/devices",
  },
  {
    path: "/settings",
    name: "settings",
    component: () => import("../views/Settings.vue"),
    meta: { requiresAuth: true, title: "Settings" },
  },
  {
    path: "/login",
    name: "login",
    component: () => import("../views/LoginView.vue"),
    meta: { guest: true, title: "Sign in" },
  },
  {
    // First-run setup only. The view redirects to /login once an account
    // exists, so the old /register URL keeps working as a redirect target.
    path: "/setup",
    alias: "/register",
    name: "register",
    component: () => import("../views/Register.vue"),
    meta: { guest: true, title: "First-run setup" },
  },
  {
    path: "/forgot-password",
    name: "forgot-password",
    component: () => import("../views/ForgotPassword.vue"),
    // Reachable while signed in too — “Forgot the current password?” in
    // Settings leads here. No guest/requiresAuth; the page manages itself.
    meta: { title: "Reset password" },
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("../views/Error404.vue"),
    meta: { title: "Not found" },
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
  // Every navigation starts at the top of the canvas.
  scrollBehavior: () => ({ left: 0, top: 0 }),
});

// "Settings · NetPulse" rather than "localhost/settings".
router.afterEach((to) => {
  const title = to.meta?.title as string | undefined;
  document.title = title ? `${title} · ${APP_NAME}` : `${APP_NAME} · Network Operations`;
});

router.beforeEach(async (to, from, next) => {
  const { useAuthStore } = await import("../stores/auth");
  const auth = useAuthStore();

  // A stored token that the API no longer accepts (unchecked "Remember me"
  // expires after an hour) is the boot-time case; say so on the login screen.
  let sessionExpired = false;
  if (auth.token && !auth.user) {
    sessionExpired = !(await auth.loadUser());
  }

  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    // Remember where the user was headed so login can resume it.
    const query: Record<string, string> = { redirect: to.fullPath };
    if (sessionExpired) query.expired = "1";
    next({ name: "login", query });
  } else if (to.meta.guest && auth.isAuthenticated) {
    next({ name: "dashboard" });
  } else {
    next();
  }
});

export default router;
