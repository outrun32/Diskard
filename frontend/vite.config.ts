import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 8702,
    proxy: {
      "/api": "http://127.0.0.1:8700",
      "/health": "http://127.0.0.1:8700",
    },
  },
  preview: {
    host: "127.0.0.1",
    port: 8702,
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});
