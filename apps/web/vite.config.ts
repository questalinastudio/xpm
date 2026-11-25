import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  build: { outDir: 'dist', sourcemap: false },
  // Local development: run the server with XPM_PUBLIC_ORIGIN=http://localhost:5173.
  server: { proxy: { '/api': 'http://localhost:3000' } },
});
