import { createRouter, createWebHistory, RouteRecordRaw } from "vue-router";

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
    meta: { requiresAuth: true },
  },
  {
    path: "/devices",
    name: "devices",
    component: () => import("../views/Devices.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/topology",
    name: "topology",
    component: () => import("../views/InteractiveTopology.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/toolbox",
    name: "toolbox",
    component: () => import("../views/Toolbox.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/logs",
    name: "logs",
    component: () => import("../views/Logs.vue"),
    meta: { requiresAuth: true },
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
    meta: { requiresAuth: true },
  },
  {
    path: "/login",
    name: "login",
    component: () => import("../views/LoginView.vue"),
    meta: { guest: true },
  },
  {
    path: "/register",
    name: "register",
    component: () => import("../views/Register.vue"),
    meta: { guest: true },
  },
  {
    path: "/forgot-password",
    name: "forgot-password",
    component: () => import("../views/ForgotPassword.vue"),
    meta: { guest: true },
  },
  {
    path: "/:pathMatch(.*)*",
    name: "not-found",
    component: () => import("../views/Error404.vue"),
  },
];

const router = createRouter({
  history: createWebHistory(),
  routes,
  // Every navigation starts at the top of the canvas.
  scrollBehavior: () => ({ left: 0, top: 0 }),
});

router.beforeEach(async (to, from, next) => {
  const { useAuthStore } = await import("../stores/auth");
  const auth = useAuthStore();
  
  if (auth.token && !auth.user) {
    await auth.loadUser();
  }

  if (to.meta.requiresAuth && !auth.isAuthenticated) {
    // Remember where the user was headed so login can resume it.
    next({ name: "login", query: { redirect: to.fullPath } });
  } else if (to.meta.guest && auth.isAuthenticated) {
    next({ name: "dashboard" });
  } else {
    next();
  }
});

export default router;
