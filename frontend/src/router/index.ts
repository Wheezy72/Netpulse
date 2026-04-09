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
    path: "/diagnostics",
    name: "diagnostics",
    component: () => import("../views/Diagnostics.vue"),
    meta: { requiresAuth: true },
  },
  {
    path: "/scanning",
    name: "scanning",
    component: () => import("../views/Scanning.vue"),
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
    path: "/automation",
    name: "automation",
    component: () => import("../views/Automation.vue"),
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
];

const router = createRouter({
  history: createWebHistory(),
  routes,
});

export default router;
