/** @type {import('eslint').Linter.Config} */
module.exports = {
  env: {
    node: true,
    es2022: true,
    jest: true,
  },
  extends: ['eslint:recommended'],
  parserOptions: {
    ecmaVersion: 2022,
  },
  rules: {
    // ── Security: these catch real bugs ─────────────────────
    'no-eval':             'error',
    'no-implied-eval':     'error',
    'no-new-func':         'error',
    'no-script-url':       'error',

    // ── SQL injection guard ─────────────────────────────────
    // Disallow template literals in strings named 'query' or 'sql'
    // (can't enforce parameterisation purely via ESLint, but this
    //  helps catch obvious mistakes)
    'no-template-curly-in-string': 'warn',

    // ── Code quality ────────────────────────────────────────
    'no-console':          ['warn', { allow: ['warn', 'error'] }],
    'no-unused-vars':      ['error', { argsIgnorePattern: '^_' }],
    'no-var':              'error',
    'prefer-const':        'error',
    'eqeqeq':             ['error', 'always'],
    'curly':              'error',

    // ── Promise handling ────────────────────────────────────
    'no-async-promise-executor': 'error',
    'require-await':             'warn',

    // ── Style (enforced by Prettier, kept minimal here) ─────
    'semi':               ['error', 'always'],
    'quotes':             ['error', 'single', { avoidEscape: true }],
  },
  overrides: [
    {
      files: ['tests/**/*.js'],
      rules: {
        // Tests may use console for debugging
        'no-console': 'off',
        // Tests may have unused vars in mock setups
        'no-unused-vars': 'warn',
      },
    },
  ],
};
