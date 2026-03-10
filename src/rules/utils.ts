import type { PolicyRule, Role, RoleBinding } from '../parser/types';

export function hasWildcard(arr: string[]): boolean {
  return arr.includes('*');
}

export function hasVerb(rule: PolicyRule, verb: string): boolean {
  return rule.verbs.includes('*') || rule.verbs.includes(verb);
}

export function hasAnyVerb(rule: PolicyRule, verbs: string[]): boolean {
  return rule.verbs.includes('*') || verbs.some(v => rule.verbs.includes(v));
}

export function hasResource(rule: PolicyRule, resource: string): boolean {
  return rule.resources.includes('*') || rule.resources.includes(resource);
}

export function resourceLabel(r: Role): string {
  const ns = r.metadata.namespace ? `${r.metadata.namespace}/` : '';
  return `${r.kind}/${ns}${r.metadata.name}`;
}

export function bindingLabel(b: RoleBinding): string {
  const ns = b.metadata.namespace ? `${b.metadata.namespace}/` : '';
  return `${b.kind}/${ns}${b.metadata.name}`;
}

export function makeRoleKey(name: string, namespace?: string): string {
  return namespace ? `${namespace}/${name}` : name;
}

export function makeSAKey(name: string, namespace: string): string {
  return `${namespace}/${name}`;
}

export const WRITE_VERBS = ['create', 'update', 'patch', 'delete', 'deletecollection'];

export function writeVerbs(): string[] {
  return WRITE_VERBS;
}

export function hasWriteVerb(rule: PolicyRule): boolean {
  return hasAnyVerb(rule, WRITE_VERBS);
}

export function isClusterAdminEquivalent(role: Role): boolean {
  for (const rule of role.rules) {
    if (rule.verbs.includes('*') && rule.resources.includes('*') && rule.apiGroups.includes('*')) return true;
  }
  return false;
}

export function isSystemResource(name: string): boolean {
  return name.startsWith('system:') || name.startsWith('kubeadm:');
}
