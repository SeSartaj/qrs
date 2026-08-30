import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'
import { fileURLToPath } from 'node:url'

// Build the SPA into the Django app's static directory so Django serves it.
// The Django view at / serves index.html; assets are under /static/frontend/.
export default defineConfig({
  plugins: [react()],
  base: '/static/frontend/',
  build: {
    outDir: fileURLToPath(new URL('../enterprise/static/frontend', import.meta.url)),
    emptyOutDir: true,
  },
})
