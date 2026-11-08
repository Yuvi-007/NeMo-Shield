import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'
import { fileURLToPath } from 'node:url'
import { defineConfig, loadEnv } from 'vite'

const ROOT = fileURLToPath(new URL('.', import.meta.url))

// https://vite.dev/config/
export default defineConfig(({ mode }) => {
  // Dev-server only, never bundled: where `npm run dev` forwards /api requests
  // when VITE_API_BASE_URL is unset. Override with NEMO_API_PROXY_TARGET.
  const env = loadEnv(mode, ROOT, '')
  const proxyTarget = env.NEMO_API_PROXY_TARGET || 'http://127.0.0.1:8000'

  return {
    plugins: [react(), tailwindcss()],
    server: {
      // Policy Hub reads the live Colang files from ../config.
      fs: { allow: ['..'] },
      proxy: {
        '/api': { target: proxyTarget, changeOrigin: true },
      },
    },
  }
})
