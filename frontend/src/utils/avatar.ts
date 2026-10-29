/**
 * Account portraits, rendered locally with DiceBear.
 *
 * The accounts in this app carry only a username (and an optional email), so
 * "personalised" means a portrait seeded by the account itself: the same
 * account always draws the same face, on every page that shows it, with no
 * network call.
 *
 * The default skin is fun-emoji — flat faces on a solid colour, closer to the
 * default streaming-profile look than line art — but every render goes through
 * the registry below so the signed-in account can switch skin without the call
 * sites knowing anything about DiceBear. The line-art skin's ink is retinted to
 * `currentColor`, so it rides the theme like every AppGlyph does.
 *
 * The seed is safe text only: percent-encoded before it reaches the generator,
 * so an account name can never smuggle markup into v-html.
 */
import { createAvatar, type Style } from "@dicebear/core";
import {
  avataaars,
  bigSmile,
  dylan,
  funEmoji,
  micah,
  notionistsNeutral,
} from "@dicebear/collection";

export const DEFAULT_AVATAR_STYLE = "fun-emoji";

/** Curated skins shown in the profile-menu picker, in display order. */
export const AVATAR_STYLES: { id: string; label: string; style: Style<any> }[] = [
  { id: "fun-emoji", label: "Emote", style: funEmoji },
  { id: "big-smile", label: "Smile", style: bigSmile },
  { id: "avataaars", label: "Classic", style: avataaars },
  { id: "micah", label: "Micah", style: micah },
  { id: "dylan", label: "Dylan", style: dylan },
  { id: "notionists", label: "Ink", style: notionistsNeutral },
];

const STYLE_BY_ID = new Map(AVATAR_STYLES.map((entry) => [entry.id, entry.style]));

// Line-art skins are monochrome by design; their ink follows the theme's text
// colour. Everything else brings its own palette and is left alone.
const LINE_ART_STYLES = new Set(["notionists"]);

/** Anything unknown (older builds, storage corruption) falls back to default. */
export function normalizeAvatarStyle(styleId: string | null | undefined): string {
  return styleId && STYLE_BY_ID.has(styleId) ? styleId : DEFAULT_AVATAR_STYLE;
}

export function avatarSeedFor(options: {
  username?: string | null;
  email?: string | null;
  fullName?: string | null;
}): string {
  const seed = options.email ?? options.username ?? options.fullName ?? "";
  return seed.trim() ? encodeURIComponent(seed.trim()) : "netpulse-account";
}

// A roster panel draws the same faces many pages in a row, and swapping skins
// re-renders them all, so the SVG strings are memoised per skin+seed+size.
const cache = new Map<string, string>();

/** Short, id-safe fragment so two avatars in one document cannot collide. */
function idSuffix(value: string): string {
  let h = 2166136261;
  for (let i = 0; i < value.length; i += 1) {
    h ^= value.charCodeAt(i);
    h = Math.imul(h, 16777619);
  }
  return (h >>> 0).toString(36);
}

/**
 * DiceBear gives every set the same internal id — `<mask id="viewboxMask">` —
 * sized to that set's own viewBox (200 square for fun-emoji, 360 for micah,
 * 560 for notionists). Several avatars are inlined side by side, and an id is
 * document-wide, so they all resolved the *first* mask in the DOM: a 24px
 * emoji at the top of the page cropped every other skin to a wedge of itself.
 * Namespacing the id per set keeps each portrait on its own mask.
 */
function namespaceIds(svg: string, suffix: string): string {
  return svg
    .replace(/\bid="([^"]+)"/g, (_match, id: string) => `id="${id}-${suffix}"`)
    .replace(/url\(#([^)]+)\)/g, (_match, id: string) => `url(#${id}-${suffix})`)
    .replace(/href="#([^"]+)"/g, (_match, id: string) => `href="#${id}-${suffix}"`);
}

export function avatarSvg(seed: string, size = 40, styleId?: string | null): string {
  const skin = normalizeAvatarStyle(styleId);
  const key = `${skin}|${seed}|${size}`;
  const cached = cache.get(key);
  if (cached) return cached;

  let svg = createAvatar(STYLE_BY_ID.get(skin)!, { seed, size }).toString();
  // DiceBear emits an RDF metadata block we do not need in the DOM.
  svg = svg.replace(/<metadata[\s\S]*?<\/metadata>/, "");
  svg = namespaceIds(svg, `${skin}-${idSuffix(`${skin}|${seed}`)}`);
  if (LINE_ART_STYLES.has(skin)) {
    // The neutral style only paints in #000 (ink) and #fff (paper silhouette).
    // The ink follows the text colour so dark and light themes both read; the
    // paper silhouette stays white over the tinted circle behind it.
    svg = svg.replace(/fill="#000(000)?"/g, 'fill="currentColor"');
  }
  // Preserve the xmlns so v-html keeps it a standalone inline SVG.
  cache.set(key, svg);
  return svg;
}
