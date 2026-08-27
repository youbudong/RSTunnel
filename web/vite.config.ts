import { defineConfig } from "vite";

// 开发服务器：管理面 REST API 监听在 internal 回环地址（默认 127.0.0.1:8080，见
// tunnel-config `internal.bind`）。同源代理避免 CORS；`VITE_API_BASE` 可覆盖。
const target = process.env.VITE_API_BASE ?? "http://127.0.0.1:8080";

export default defineConfig({
  server: {
    port: 5173,
    proxy: {
      "/auth": { target, changeOrigin: true },
      "/enroll": { target, changeOrigin: true },
      "/api": { target, changeOrigin: true },
      "/openapi.json": { target, changeOrigin: true },
      "/ws": { target, changeOrigin: true, ws: true },
    },
  },
});
