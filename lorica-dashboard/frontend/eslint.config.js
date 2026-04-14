// Copyright 2026 Rwx-G (Lorica)
//
// ESLint flat-config for the Lorica dashboard frontend. The goal of
// this file is narrowly scoped: enforce the XSS and template-injection
// rules that Semgrep OSS cannot catch because it lacks a Svelte
// parser (audit coverage gap, pre-v1.3.0 follow-up).
//
// The audit confirmed 0 exploitable `{@html}` sites in v1.3.0, all
// interpolating module-scoped static SVG `const` identifiers. This
// ruleset enforces that going forward: `svelte/no-at-html-tags` is
// set to `warn` rather than `error` so the existing safe sites keep
// compiling, but any NEW `{@html}` usage shows up in `pnpm lint` and
// has to be justified in review.
//
// Run locally:  pnpm lint
// Wired into CI in .github/workflows/ci.yml as part of the Lint job.

import js from "@eslint/js";
import svelte from "eslint-plugin-svelte";
import svelteParser from "svelte-eslint-parser";
import tsParser from "@typescript-eslint/parser";
import globals from "globals";

export default [
  // Base JS recommended rules.
  js.configs.recommended,

  // Svelte plugin: recommended rules across .svelte files. Covers:
  //   svelte/no-at-html-tags         (warn on every {@html ...})
  //   svelte/no-target-blank         (rel=noopener required on target=_blank)
  //   svelte/valid-compile           (catches unsafe compile errors)
  //   svelte/no-inner-declarations
  ...svelte.configs["flat/recommended"],

  {
    // Apply to all TS / JS / Svelte under src/
    files: ["src/**/*.{js,mjs,ts,svelte}"],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        extraFileExtensions: [".svelte"],
        sourceType: "module",
        ecmaVersion: 2023,
      },
      globals: {
        ...globals.browser,
        ...globals.node,
      },
    },
    rules: {
      // XSS-adjacent hardening: none of these should ever show up in
      // the frontend, but being explicit is the point of a lint gate.
      "no-eval": "error",
      "no-implied-eval": "error",
      "no-new-func": "error",
      "no-script-url": "error",
      // Dead code that the eslint base rules flag aggressively but
      // that Svelte's reactive-declaration syntax tickles; downgrade.
      "no-unused-vars": "off",
      "no-undef": "off", // TypeScript handles this.
    },
  },

  // Svelte-specific file rules.
  {
    files: ["**/*.svelte"],
    languageOptions: {
      parser: svelteParser,
      parserOptions: {
        parser: tsParser,
        extraFileExtensions: [".svelte"],
        sourceType: "module",
      },
    },
  },

  // Ignore built artifacts, vendored code, and test fixtures.
  {
    ignores: [
      "dist/**",
      "build/**",
      "node_modules/**",
      "coverage/**",
      "**/*.generated.ts",
      "**/__snapshots__/**",
    ],
  },
];
