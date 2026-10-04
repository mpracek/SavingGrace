import { defineConfig } from 'vitest/config';
import { fileURLToPath } from 'node:url';

const src = (p: string) => fileURLToPath(new URL(`./packages/${p}/src/index.ts`, import.meta.url));

export default defineConfig({
  resolve: {
    alias: {
      '@savinggrace/shared-types': src('shared-types'),
      '@savinggrace/domain-matcher': src('domain-matcher'),
      '@savinggrace/rule-engine': src('rule-engine'),
      '@savinggrace/configuration': src('configuration'),
      '@savinggrace/database': src('database'),
    },
  },
  test: { include: ['tests/**/*.test.ts'] },
});
