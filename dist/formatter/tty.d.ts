import type { Violation } from '../rules/types';
import type { ServiceAccountScore } from '../engine/scorer';
export declare function formatTTY(violations: Violation[], scores: ServiceAccountScore[], useColor: boolean): string;
