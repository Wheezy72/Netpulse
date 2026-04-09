import { defineStore } from "pinia";
import { ref } from "vue";

type Theme = "nightshade" | "sysadmin";

export const useUiStore = defineStore("ui", () => {
  const theme = ref<Theme>(
    (localStorage.getItem("np-theme") as Theme) || "nightshade"
  );
  const sidebarExpanded = ref(true);
  const commandPaletteOpen = ref(false);

  function setTheme(t: Theme) {
    theme.value = t;
    localStorage.setItem("np-theme", t);
    document.body.classList.remove("theme-nightshade", "theme-sysadmin");
    document.body.classList.add(`theme-${t}`);
  }

  function toggleSidebar() {
    sidebarExpanded.value = !sidebarExpanded.value;
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
