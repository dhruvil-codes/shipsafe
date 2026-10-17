# GradientASCII

Installed from the official React Bits registry with:

```sh
npx shadcn@latest add @react-bits/GradientASCII-JS-CSS --yes --path components/react-bits
```

Source: https://reactbits.dev/r/GradientASCII-JS-CSS.json
Documentation: https://www.reactbits.dev/backgrounds/gradient-ascii
Upstream license is preserved in `LICENSE.md`.

Local changes: added a `paused` property that stops the animation loop and pointer
effects; removed forced WebGL context loss from effect cleanup so React Strict
Mode can remount the renderer. Cleanup still deletes the textures, framebuffers,
programs, and vertex array. Keep these changes when updating the registry files.

`HeroASCII.tsx` owns the light blue palette, lazy loading, pixel ratio limit,
and live reduced-motion preference updates. The hero animates automatically.
