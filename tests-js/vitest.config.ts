import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'node',
    include: ['**/*.test.ts', '**/*.test.mjs'],
    // Git/Python fixtures share CI CPUs with the other workspace checks.
    maxWorkers: process.env.GITHUB_ACTIONS ? 2 : undefined,
  },
})
