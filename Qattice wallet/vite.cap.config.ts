import { defineConfig } from "vite";
import viteReact from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { resolve } from "path";

/**
 * Minimal static SPA build for Capacitor (Android/iOS).
 * No SSR, no Nitro, no TanStack Start — just React + Tailwind.
 * Output: dist-cap/  (Capacitor webDir)
 *
 * Usage:
 *   npm run build:cap       → builds to dist-cap/
 *   npx cap sync android    → copies dist-cap/ into android/assets/public/
 *   cd android && gradlew assembleDebug  → produces APK
 */
export default defineConfig({
  root: ".",
  build: {
    outDir: "dist-cap",
    emptyOutDir: true,
    rollupOptions: {
      input: resolve(__dirname, "index.cap.html"),
    },
  },
  resolve: {
    alias: {
      "@": resolve(__dirname, "src"),
    },
  },
  plugins: [tailwindcss(), viteReact()],
  define: {
    // Capacitor apps read from .env at build time via VITE_ prefix
    "import.meta.env.VITE_NODE_URL": JSON.stringify(process.env.VITE_NODE_URL ?? ""),
    "import.meta.env.VITE_CHAIN_ID": JSON.stringify(
      process.env.VITE_CHAIN_ID ?? "qcb-devnet-fee-settle",
    ),
    "import.meta.env.VITE_WALLET_ADDRESS": JSON.stringify(process.env.VITE_WALLET_ADDRESS ?? ""),
  },
});
