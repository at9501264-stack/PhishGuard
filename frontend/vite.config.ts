import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'
import { defineConfig } from 'vite'

// Backend origin for the dev/preview proxy. Override with e.g.
//   PHISHGUARD_API=http://127.0.0.1:8001 npm run dev
const backend = (process.env.PHISHGUARD_API || 'http://localhost:8000').replace(/\/+$/, '')

// '/api/' keeps the trailing slash so client routes like /api-guide are not proxied to the backend.
const proxied = ['/api/', '/docs', '/redoc', '/openapi.json', '/static', '/screenshots']
const proxy = Object.fromEntries(proxied.map((p) => [p, { target: backend, changeOrigin: true }]))

// https://vite.dev/config/
export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy,
  },
  preview: {
    proxy,
  },
  build: {
    chunkSizeWarningLimit: 1500,
  },
})
