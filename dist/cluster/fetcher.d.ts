import type { K8sResource } from '../parser/types';
export interface ClusterFetchOptions {
    context?: string;
    namespace?: string;
    allNamespaces: boolean;
}
export declare function fetchClusterResources(opts: ClusterFetchOptions): Promise<K8sResource[]>;
