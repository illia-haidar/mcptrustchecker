/*! MCP Trust Checker · https://mcptrustchecker.com · support@mcptrustchecker.com · © 2026 Illia Haidar · MIT */
/**
 * Detector registry. The engine runs every registered detector, then runs the
 * toxic-flow analysis and integrity check (which need cross-cutting state and
 * are wired directly in the engine).
 */

import type { Detector } from '../types.js';
import { metaDetector } from './meta.js';
import { unicodeDetector } from './unicode.js';
import { injectionDetector } from './injection.js';
import { capabilityDetector } from './capability.js';
import { collisionDetector } from './collision.js';
import { supplyChainDetector } from './supplyChain.js';
import { postureDetector } from './posture.js';
import { sourceDetector } from './source.js';

export const DETECTORS: Detector[] = [
  metaDetector,
  unicodeDetector,
  injectionDetector,
  capabilityDetector,
  collisionDetector,
  supplyChainDetector,
  postureDetector,
  sourceDetector,
];

export {
  metaDetector,
  unicodeDetector,
  injectionDetector,
  capabilityDetector,
  collisionDetector,
  supplyChainDetector,
  postureDetector,
  sourceDetector,
};
export { analyzeToxicFlows } from './toxicFlow.js';
