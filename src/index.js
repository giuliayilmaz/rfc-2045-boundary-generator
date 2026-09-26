/**
 * Public entry point for the RFC 2045 boundary generator library.
 *
 * Re-exports the generator factory and convenience function from core.
 */
export { createBoundaryGenerator, generateBoundary } from './core.js';
