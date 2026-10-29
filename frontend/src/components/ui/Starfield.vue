<script setup lang="ts">
/**
 * Starfield background — a port of the shadcn.io "starfield" background
 * (shadcn.io/background/starfield), built to its documented behaviour:
 *
 *   "each one appears small and dim near the centre, then speeds up, grows,
 *    brightens and streaks into a short comet as it passes the edge, while
 *    distant stars hold still behind them."
 *
 * Drawn on one <canvas>, deliberately. The first version was ~300 DOM spans,
 * each with its own CSS animation, a nested tail element and `will-change` —
 * which is 300 composited layers that the whole document has to respect. The
 * app is full of `backdrop-filter` glass panels sitting over this background,
 * so every animated layer forced those panels to re-blur every frame: the
 * field was smooth on an empty login page and made the console crawl.
 *
 * A single canvas with ~200 short strokes at 30fps is one rasterising surface,
 * a few hundred microseconds of work, and nothing for the rest of the document
 * to reconcile. Motion is time-based rather than frame-based, so the same
 * climb holds at any refresh rate.
 *
 * The three things that make it read as flight rather than dust:
 *
 *   1. Acceleration. A star's radius grows the way 1/z grows — barely at
 *      first, then fast. The radius curve below is the perspective curve,
 *      never a constant rate.
 *   2. A late streak. The tail stays a point for most of the flight and only
 *      stretches in the last third, once the star is already quick.
 *   3. The still scatter. Stars "too far away to move" hold position behind
 *      the flying field. That is where the sky's depth comes from.
 *
 * Placement comes from a hash of the star's index, not Math.random(), so a
 * rebuild after a resize re-seeds the identical field instead of jumping.
 */
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

type Fade = "none" | "radial" | "top" | "bottom";

const props = withDefaults(
  defineProps<{
    /** How many stars fly at once in a full-size box. */
    count?: number;
    /** Edge treatment, applied per pixel rather than by a CSS mask. */
    fade?: Fade;
    /** Flight-speed multiplier; 1 is a calm cruise, 3 is warp. */
    speed?: number;
    /** Any CSS colour. Left unset so the theme tokens supply it. */
    starColor?: string;
  }>(),
  { count: 220, fade: "radial", speed: 1, starColor: undefined },
);

// A 1280x720 box is the reference size for "a full page". A field needs density
// to read at all, so the scaling is a square root rather than a linear ratio.
const REFERENCE_AREA = 1280 * 720;
const MAX_COUNT = 300;
const MIN_FLYING = 24;
/** Seconds for the farthest, slowest star at speed 1 — a deliberate cruise. */
const FAR_SECONDS = 28;
/** ...and for the nearest, fastest one. */
const NEAR_SECONDS = 15;
/**
 * Frames per second for the field. Stars cross in 15–28 seconds, so 30fps is
 * indistinguishable from 60 here while halving everything the browser redoes
 * behind the app's blurred panels.
 */
const TARGET_FPS = 30;
/** Capping the backing store keeps a 4K/Retina canvas from quadrupling fill. */
const MAX_DPR = 1.5;

// The motion curve, sampled per frame: radius progress at each stop, the
// matching brightness and tail-length factors. These are the numbers the CSS
// keyframe version was tuned to, so the look is unchanged.
const STOPS = [0, 0.08, 0.35, 0.62, 0.84, 1];
const RADIUS = [0, 0.006, 0.09, 0.32, 0.68, 1];
const ALPHA = [0, 0.45, 0.75, 1, 1, 1];
const TAIL = [0.06, 0.08, 0.14, 0.3, 0.68, 1];

interface Star {
  cos: number;
  sin: number;
  outer: number;
  length: number;
  thick: number;
  opacity: number;
  seconds: number;
  /** Offset into the flight, so the field is mid-journey on first paint. */
  phase: number;
}

interface Dust {
  x: number;
  y: number;
  size: number;
  opacity: number;
}

/** Deterministic value in [0,1) so the same index always seeds the same star. */
function hash(index: number, salt: number): number {
  const x = Math.sin(index * 127.1 + salt * 311.7) * 43758.5453;
  return x - Math.floor(x);
}

/** Piecewise-eased sample of the curves above at progress `t`. */
function sample(values: number[], t: number): number {
  for (let i = 1; i < STOPS.length; i += 1) {
    if (t <= STOPS[i]) {
      const span = STOPS[i] - STOPS[i - 1] || 1;
      const f = (t - STOPS[i - 1]) / span;
      const eased = f * f * (3 - 2 * f);
      return values[i - 1] + (values[i] - values[i - 1]) * eased;
    }
  }
  return values[values.length - 1];
}

const canvas = ref<HTMLCanvasElement | null>(null);

let ctx: CanvasRenderingContext2D | null = null;
let stars: Star[] = [];
let dust: Dust[] = [];
/** The still scatter never moves, so it is rasterised once per size/colour. */
let dustLayer: HTMLCanvasElement | null = null;
let colour = "#e6e8f0";
let width = 0;
let height = 0;
let dpr = 1;
let elapsed = 0;
let lastPaint = 0;
let raf = 0;
let visible = true;
let resizeObserver: ResizeObserver | null = null;
let intersectionObserver: IntersectionObserver | null = null;
let themeObserver: MutationObserver | null = null;
let lastSignature = "";

const reducedMotion = (): boolean =>
  typeof window !== "undefined" &&
  window.matchMedia?.("(prefers-reduced-motion: reduce)")?.matches === true;

/**
 * The field takes the theme's text ink — near-white on Nightshade, near-black
 * on SysAdmin — which is what shadcn's `starColor: var(--foreground)` does.
 * Resolved from the element's computed `color`, because reading a custom
 * property back returns the literal `var(--np-text)` token, not its value.
 */
function resolveColour(): void {
  const el = canvas.value;
  if (!el) return;
  if (props.starColor) el.style.color = props.starColor;
  const resolved = getComputedStyle(el).color;
  if (resolved && resolved !== colour) {
    colour = resolved;
    // The dust is baked in this colour; throw the bake away rather than let it
    // keep the previous theme's ink.
    dustLayer = null;
  }
}

/**
 * Dust sits at a fixed position forever, so 130-odd fillRects per frame was
 * pure waste — rasterise it once, then blit one image per frame.
 */
function bakeDust(): void {
  if (!width || !height) return;
  const layer = document.createElement("canvas");
  layer.width = Math.max(1, Math.round(width * dpr));
  layer.height = Math.max(1, Math.round(height * dpr));
  const dctx = layer.getContext("2d");
  if (!dctx) return;
  dctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  dctx.fillStyle = colour;
  for (const mote of dust) {
    dctx.globalAlpha = mote.opacity * edgeAlpha(mote.x, mote.y);
    dctx.fillRect(mote.x, mote.y, mote.size, mote.size);
  }
  dctx.globalAlpha = 1;
  dustLayer = layer;
}

function rebuild(w: number, h: number): void {
  width = w;
  height = h;
  if (!w || !h) return;

  const ratio = Math.min(Math.sqrt((w * h) / REFERENCE_AREA), 1);
  const capped = Math.max(0, Math.min(props.count, MAX_COUNT));
  const flying = Math.max(MIN_FLYING, Math.round(capped * ratio));

  // A resize that changes nothing must not re-scatter the field.
  const signature = `${flying}|${Math.round(w)}x${Math.round(h)}`;
  if (signature === lastSignature) return;
  lastSignature = signature;

  const speed = props.speed > 0 ? props.speed : 1;
  // Past the farthest corner, so a star leaves the viewport rather than
  // resetting where it can be seen.
  const reach = Math.hypot(w, h) / 2;

  stars = Array.from({ length: flying }, (_, i) => {
    const depth = 0.15 + hash(i, 1) * 0.85;
    const seconds = (FAR_SECONDS - depth * (FAR_SECONDS - NEAR_SECONDS)) / speed;
    // The golden angle, nudged per star, spreads directions evenly instead of
    // leaving the random clumps that show up as empty wedges.
    const angle = (((i * 137.508 + hash(i, 7) * 26) % 360) * Math.PI) / 180;
    return {
      cos: Math.cos(angle),
      sin: Math.sin(angle),
      outer: reach * (1.05 + hash(i, 2) * 0.45),
      length: (4 + depth * 20) * (1 + (speed - 1) * 0.45),
      thick: 1 + depth * 1.2,
      opacity: 0.4 + depth * 0.55,
      seconds,
      phase: hash(i, 3),
    };
  });

  dust = Array.from({ length: Math.round(flying * 0.6) }, (_, i) => ({
    x: hash(i, 11) * w,
    y: hash(i, 12) * h,
    size: 1 + hash(i, 13) * 1.7,
    opacity: 0.16 + hash(i, 14) * 0.42,
  }));

  // The baked layer matches the previous size and ink; both may have changed.
  dustLayer = null;
}

/** Edge treatment, evaluated per star instead of by masking the whole layer. */
function edgeAlpha(x: number, y: number): number {
  if (props.fade === "none") return 1;
  if (props.fade === "top") return Math.min(1, Math.max(0, y / (height * 0.6)));
  if (props.fade === "bottom") {
    return Math.min(1, Math.max(0, (height - y) / (height * 0.6)));
  }
  const cx = width / 2;
  const cy = height / 2;
  const d = Math.hypot(x - cx, y - cy) / (Math.hypot(width, height) / 2);
  // Opaque until the outer band, then a short fade so stars thin out at the
  // rim rather than being cut off by the canvas edge.
  return d <= 0.84 ? 1 : Math.max(0, (1 - d) / 0.16);
}

function draw(): void {
  if (!ctx) return;
  const cx = width / 2;
  const cy = height / 2;

  ctx.clearRect(0, 0, width, height);

  if (!dustLayer) bakeDust();
  if (dustLayer) ctx.drawImage(dustLayer, 0, 0, width, height);

  ctx.strokeStyle = colour;
  ctx.lineCap = "round";

  // Stars are collected into a handful of buckets by brightness and thickness,
  // then stroked once per bucket. One stroke per star meant ~220 stroke calls a
  // frame, which showed up as the single largest cost in the field.
  const buckets = new Map<string, { alpha: number; width: number; path: Path2D }>();

  for (const star of stars) {
    const t = (elapsed / star.seconds + star.phase) % 1;
    const radius = sample(RADIUS, t) * star.outer;
    const tail = Math.max(0.6, sample(TAIL, t) * star.length);
    const hx = cx + star.cos * radius;
    const hy = cy + star.sin * radius;

    const alpha = star.opacity * sample(ALPHA, t) * edgeAlpha(hx, hy);
    if (alpha <= 0.02) continue;
    const key = `${Math.round(alpha * 20)}|${Math.round(star.thick * 2)}`;
    let bucket = buckets.get(key);
    if (!bucket) {
      bucket = { alpha, width: star.thick, path: new Path2D() };
      buckets.set(key, bucket);
    }
    bucket.path.moveTo(hx - star.cos * tail, hy - star.sin * tail);
    bucket.path.lineTo(hx, hy);
  }

  for (const bucket of buckets.values()) {
    ctx.globalAlpha = bucket.alpha;
    ctx.lineWidth = bucket.width;
    ctx.stroke(bucket.path);
  }

  ctx.globalAlpha = 1;
}

function frame(now: number): void {
  raf = requestAnimationFrame(frame);
  // A hidden tab already stops rAF; this also covers the browser throttling
  // frames to 1Hz on a background window, where the delta would be huge.
  if (!visible) return;
  if (now - lastPaint < 1000 / TARGET_FPS - 1) return;
  const dt = lastPaint ? Math.min((now - lastPaint) / 1000, 0.25) : 0;
  lastPaint = now;
  elapsed += dt;
  draw();
}

function start(): void {
  if (reducedMotion()) {
    // A still field, already spread across the sky — not an empty background.
    elapsed = 4.2;
    draw();
    return;
  }
  if (raf) return;
  lastPaint = 0;
  raf = requestAnimationFrame(frame);
}

function stop(): void {
  if (raf) cancelAnimationFrame(raf);
  raf = 0;
}

function resize(w: number, h: number): void {
  const el = canvas.value;
  if (!el || !w || !h) return;
  dpr = Math.min(window.devicePixelRatio || 1, MAX_DPR);
  const pw = Math.round(w * dpr);
  const ph = Math.round(h * dpr);
  if (el.width !== pw || el.height !== ph) {
    el.width = pw;
    el.height = ph;
  }
  ctx = el.getContext("2d");
  if (!ctx) return;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  rebuild(w, h);
  draw();
}

function measure(entry?: ResizeObserverEntry): void {
  const el = canvas.value;
  if (!el) return;
  const rect = entry?.contentRect;
  resize(rect ? rect.width : el.clientWidth, rect ? rect.height : el.clientHeight);
}

function onWindowResize(): void {
  measure();
}

function onVisibilityChange(): void {
  visible = document.visibilityState === "visible";
  if (visible) {
    start();
  } else {
    stop();
  }
}

onMounted(() => {
  const el = canvas.value;
  if (!el) return;

  resolveColour();
  resize(el.clientWidth, el.clientHeight);

  resizeObserver = new ResizeObserver((entries) => {
    measure(entries[entries.length - 1]);
  });
  resizeObserver.observe(el);
  window.addEventListener("resize", onWindowResize);
  document.addEventListener("visibilitychange", onVisibilityChange);

  // Offscreen (a background tab, a collapsed layout) means nothing to draw.
  intersectionObserver = new IntersectionObserver((entries) => {
    const entry = entries[entries.length - 1];
    if (!entry) return;
    visible = entry.isIntersecting && document.visibilityState === "visible";
    if (visible) start();
    else stop();
  });
  intersectionObserver.observe(el);

  // The theme lives on <body> as a class, so watch for the swap and repaint in
  // the new ink rather than keeping the old palette's stars.
  themeObserver = new MutationObserver(() => {
    resolveColour();
    draw();
  });
  themeObserver.observe(document.body, { attributes: true, attributeFilter: ["class"] });

  start();
});

onBeforeUnmount(() => {
  stop();
  resizeObserver?.disconnect();
  resizeObserver = null;
  intersectionObserver?.disconnect();
  intersectionObserver = null;
  themeObserver?.disconnect();
  themeObserver = null;
  window.removeEventListener("resize", onWindowResize);
  document.removeEventListener("visibilitychange", onVisibilityChange);
});

watch(
  () => [props.count, props.speed, props.starColor, props.fade],
  () => {
    lastSignature = "";
    resolveColour();
    rebuild(width, height);
    draw();
  },
);
</script>

<template>
  <canvas ref="canvas" data-slot="starfield" class="np-stars" aria-hidden="true" />
</template>
