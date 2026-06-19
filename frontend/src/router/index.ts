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
    path: "/toolbox",
    name: "toolbox",
    component: () => import("../views/Toolbox.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/packets",
    name: "packets",
    component: () => import("../views/PacketBrowser.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/logs",
    name: "logs",
    component: () => import("../views/Logs.vue"),
    meta: { requiresAuth: true },
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
    component: () => import("../views/Login.vue"),
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
});

export default router;
