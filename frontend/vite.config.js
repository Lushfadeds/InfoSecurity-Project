import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  root: '.',
  build: {
    // Output into Flask static folder so Flask can serve the built files directly
    outDir: path.resolve(__dirname, '..', 'static', 'react'),
    emptyOutDir: true,
    assetsDir: 'assets',
    rollupOptions: {
      output: {
        // keep stable names (no hashes) for easy inclusion in Jinja templates
        entryFileNames: 'assets/[name].js',
        chunkFileNames: 'assets/[name].js',
        assetFileNames: 'assets/[name].[ext]'
      }
    }
  }
})
