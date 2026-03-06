module.exports = {
    testEnvironment: 'node',
    testMatch: ['**/tests/**/*.test.js'],
    collectCoverage: true,
    coverageDirectory: 'coverage',
    coverageReporters: ['text', 'lcov', 'clover'],
    coveragePathIgnorePatterns: ['/node_modules/', '/tests/'],
    verbose: true,
    testTimeout: 15000,
    setupFilesAfterSetup: [],
    clearMocks: true,
    restoreMocks: true,
};
