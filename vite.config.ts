import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: path.resolve(__dirname, 'dist/frontend'),
    lib: {
      entry: path.resolve(__dirname, 'frontend/index.tsx'),
      name: 'BurpLikeScannerFrontend',
      formats: ['es'],
      fileName: (format) => `index.${format}.js`,
    },
    rollupOptions: {
      external: ['@caido/sdk-frontend', 'react', 'react-dom'],
      output: {
        globals: {
          react: 'React',
          'react-dom': 'ReactDOM',
          '@caido/sdk-frontend': 'CaidoSDK',
        },
        entryFileNames: `assets/[name].js`,
        chunkFileNames: `assets/[name].js`,
        assetFileNames: `assets/[name].[ext]`
      }
    },
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './'),
    },
  },
  server: {
    cors: true, // Added for Caido Devtools troubleshooting
    hmr: {
      protocol: 'ws',
      host: 'localhost'
    }
  }
}) 