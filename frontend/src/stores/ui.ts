import { defineStore } from "pinia";
import { nextTick, ref } from "vue";

type Theme = "nightshade" | "sysadmin";
type ThemeOrigin = { x: number; y: number } | undefined;

const THEME_FADE_MS = 280;

function prefersReducedMotion(): boolean {
  return (
    typeof window !== "undefined" &&
    window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches === true
  );
}

function applyThemeClass(t: Theme): void {
  document.body.classList.remove("theme-nightshade", "theme-sysadmin");
  document.body.classList.add(`theme-${t}`);
}

export const useUiStore = defineStore("ui", () => {
  const theme = ref<Theme>(
    (localStorage.getItem("np-theme") as Theme) || "nightshade"
  );
  const sidebarExpanded = ref(
    localStorage.getItem("np-sidebar-expanded") !== "false"
  );
  const commandPaletteOpen = ref(false);

  /**
   * Swap themes through the browser's View Transitions API so the new palette
   * is revealed by a circle growing from the control that was clicked, rather
   * than by a coloured sheet wiping across the interface. Browsers without the
   * API get a short cross-fade instead of the old opaque sweep.
   */
  function setTheme(t: Theme, origin?: ThemeOrigin): void {
    const switching = theme.value !== t;
    localStorage.setItem("np-theme", t);

    if (!switching || typeof document === "undefined") {
      theme.value = t;
      applyThemeClass(t);
      return;
    }

    const apply = async (): Promise<void> => {
      theme.value = t;
      applyThemeClass(t);
      // Let Vue paint the new classes before the new snapshot is taken.
      await nextTick();
    };

    const root = document.documentElement;
    const doc = document as Document & {
      startViewTransition?: (callback: () => Promise<void> | void) => {
        ready: Promise<void>;
        finished: Promise<void>;
      };
    };

    if (typeof doc.startViewTransition !== "function" || prefersReducedMotion()) {
      void apply();
      root.classList.add("np-theme-fallback");
      window.setTimeout(() => root.classList.remove("np-theme-fallback"), THEME_FADE_MS);
      return;
    }

    const x = origin?.x ?? window.innerWidth - 40;
    const y = origin?.y ?? 40;
    // Radius to the furthest corner, so the reveal always finishes off-screen.
    const radius = Math.hypot(
      Math.max(x, window.innerWidth - x),
      Math.max(y, window.innerHeight - y)
    );

    const transition = doc.startViewTransition(apply);

    transition.ready
      .then(() => {
        root.animate(
          {
            clipPath: [
              `circle(0px at ${x}px ${y}px)`,
              `circle(${radius}px at ${x}px ${y}px)`,
            ],
          },
          {
            duration: 460,
            easing: "cubic-bezier(0.22, 0.61, 0.36, 1)",
            pseudoElement: "::view-transition-new(root)",
          }
        );
      })
      .catch(() => {
        // A skipped transition is not an error; the class swap already landed.
      });
  }

  function toggleSidebar() {
    sidebarExpanded.value = !sidebarExpanded.value;
    localStorage.setItem("np-sidebar-expanded", String(sidebarExpanded.value));
  }

  function openCommandPalette() {
    commandPaletteOpen.value = true;
  }

  function closeCommandPalette() {
    commandPaletteOpen.value = false;
  }

  // Apply the stored theme immediately on import.
  setTheme(theme.value);

  return {
    theme,
    sidebarExpanded,
    commandPaletteOpen,
    setTheme,
    toggleSidebar,
    openCommandPalette,
    closeCommandPalette,
  };
});
