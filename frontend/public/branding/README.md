# Custom logo

Drop a file here to replace the drawn NetPulse mark. No code change or rebuild
of the component is needed — Vite serves this directory at `/branding/`.

Accepted names, tried in this order:

| File            | Notes                                              |
| --------------- | -------------------------------------------------- |
| `logo.svg`      | Sharpest; keep it `currentColor`-free if it is art |
| `logo.gif`      | Animated logos work; keep it under a few hundred KB |
| `logo.png`      | Transparent background recommended                  |
| `logo.webp`     | Smallest raster option                              |

The image is rendered inside a 32–36 px rounded tile in the navigation rail and
a 32 px tile on mobile, so square artwork with a little padding reads best.

If the file is missing, returns an error, or cannot be decoded, the app falls
back to its built-in animated mark and keeps running — a broken logo can never
leave the shell without one. Delete the file to get the built-in mark back.
