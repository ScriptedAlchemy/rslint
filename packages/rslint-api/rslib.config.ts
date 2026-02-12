import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from '@rslib/core';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export default defineConfig({
  lib: [
    {
      format: 'esm',
      dts: {
        bundle: true,
      },
    },
  ],
  source: {
    tsconfigPath: './tsconfig.build.json',
  },
  resolve: {
    alias: {
      '@typescript/api': path.resolve(
        __dirname,
        '../../typescript-go/_packages/api/src/api.ts',
      ),
      '@typescript/ast': path.resolve(
        __dirname,
        '../../typescript-go/_packages/ast/src/index.ts',
      ),
      '@typescript/libsyncrpc': false,
    },
  },
  tools: {
    rspack(config) {
      if (!config.resolve?.conditionNames) {
        config.resolve.conditionNames = ['...'];
      }
      config.resolve.conditionNames.unshift('@typescript/source');
      return config;
    },
  },
});
