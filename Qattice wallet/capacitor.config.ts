import type { CapacitorConfig } from "@capacitor/cli";

const config: CapacitorConfig = {
  appId: "com.qattice.wallet",
  appName: "Qattice",
  webDir: "dist-cap",
  android: {
    buildOptions: {
      // Produce a debug APK by default. For release: set keystorePath etc.
    },
  },
  server: {
    // When VITE_NODE_URL is set at build time, the app calls the real node.
    // cleartext traffic is needed for http:// devnet addresses on Android.
    cleartext: true,
  },
};

export default config;
