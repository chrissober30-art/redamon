import { defineConfig } from 'vitest/config'
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src'),
    },
  },
  test: {
    environment: 'jsdom',
    css: { modules: { classNameStrategy: 'non-scoped' } },
    setupFiles: ['./vitest.setup.ts'],
    // React 19 strips `act` from the production build. The webapp container
    // bakes in NODE_ENV=production, so without this override every
    // render()-based test would fail with "React.act is not a function".
    env: { NODE_ENV: 'test' },
  },
})
