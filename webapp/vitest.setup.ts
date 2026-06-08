/**
 * Vitest global setup.
 *
 * Registers @testing-library/jest-dom matchers (toBeInTheDocument, etc.)
 * so component tests can assert against DOM presence. Without this, vitest's
 * expect throws "Invalid Chai property: toBeInTheDocument".
 */
import '@testing-library/jest-dom/vitest'
