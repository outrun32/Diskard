import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({mode}) => {
 const env=loadEnv(mode, ".", "");
 const target=env.DISKARD_API_PROXY || "http://127.0.0.1:8700";
 const proxy={target,changeOrigin:true,rewriteWsOrigin:false,configure(server: any){server.on("proxyReq",(request:any)=>{request.setHeader("Origin",new URL(target).origin);});}};
 return {
  plugins: [react()],
  server: {
    host: "127.0.0.1",
    port: 8702,
    strictPort: true,
    proxy: {
      "/api": proxy,
      "/health": proxy,
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
};});
