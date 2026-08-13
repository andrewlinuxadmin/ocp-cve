import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  // Served from https://andrewlinuxadmin.github.io/ocp-cve/ (GitHub Pages project site)
  base: '/ocp-cve/',
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: undefined
      }
    }
  }
});
