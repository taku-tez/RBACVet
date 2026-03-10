import type { K8sResource } from '../parser/types';
export type DiffStatus = 'added' | 'removed' | 'changed';
export interface FieldChange {
    field: string;
    clusterValue: unknown;
    localValue: unknown;
}
export interface DiffEntry {
    status: DiffStatus;
    kind: string;
    name: string;
    namespace?: string;
    clusterResource?: K8sResource;
    localResource?: K8sResource;
    changes?: FieldChange[];
}
export declare function diffResources(clusterResources: K8sResource[], localResources: K8sResource[]): DiffEntry[];
