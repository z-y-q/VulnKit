import { defineConfig } from 'vitest/config';
import { svelte } from '@sveltejs/vite-plugin-svelte';
import { fileURLToPath } from 'node:url';

export default defineConfig({
  plugins: [
    svelte(),
  ],
  test: {
    environment: 'jsdom',
    globals: true,
    include: ['test/**/*.test.ts'],
    setupFiles: ['test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      reportsDirectory: 'coverage',
      include: ['src/**/*.{ts,svelte}'],
      exclude: [
        'src/**/*.d.ts',
        'src/**/index.ts',
        'src/entrypoints/**',
      ],
      // 阈值略低于当前真实基线（lines 13.8% / statements 10.7% / branches 11.8% / functions 9.8%），
      // 保证 green 并卡住回归；后续随 §3.4 补测逐步提到 60%（docs/个人版项目优化路线.md §3.1 阈值路线）
      thresholds: {
        lines: 12,
        functions: 8,
        statements: 9,
        branches: 10,
      },
    },
  },
  resolve: {
    alias: {
      '@': fileURLToPath(new URL('./src', import.meta.url)),
    },
  },
});
