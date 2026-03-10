import { describe, it, expect } from 'vitest';
import { parseFile } from '../src/parser/parser';

describe('parseFile', () => {
  it('parses a single Role', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('Role');
    const role = result.resources[0] as import('../src/parser/types').Role;
    expect(role.metadata.name).toBe('pod-reader');
    expect(role.metadata.namespace).toBe('default');
    expect(role.rules).toHaveLength(1);
    expect(role.rules[0].verbs).toEqual(['get', 'list']);
  });

  it('parses a ClusterRole', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-reader
rules:
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get"]
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources[0].kind).toBe('ClusterRole');
  });

  it('parses a RoleBinding', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: test-binding
  namespace: default
subjects:
- kind: ServiceAccount
  name: my-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources[0].kind).toBe('RoleBinding');
    const binding = result.resources[0] as import('../src/parser/types').RoleBinding;
    expect(binding.subjects).toHaveLength(1);
    expect(binding.subjects[0].name).toBe('my-sa');
    expect(binding.roleRef.name).toBe('pod-reader');
  });

  it('parses a ServiceAccount', () => {
    const yaml = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
  namespace: default
automountServiceAccountToken: false
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources[0].kind).toBe('ServiceAccount');
    const sa = result.resources[0] as import('../src/parser/types').ServiceAccount;
    expect(sa.metadata.name).toBe('my-sa');
    expect(sa.automountServiceAccountToken).toBe(false);
  });

  it('parses multi-document YAML stream', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: role-one
  namespace: default
rules: []
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: cluster-role-one
rules: []
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-one
  namespace: default
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(3);
    expect(result.resources.map(r => r.kind)).toEqual(['Role', 'ClusterRole', 'ServiceAccount']);
  });

  it('skips unknown kinds without error', () => {
    const yaml = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
spec:
  replicas: 1
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
  });

  it('handles missing metadata.name gracefully', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: default
rules: []
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(0);
  });

  it('handles empty rules array', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: empty-role
  namespace: default
rules: []
`;
    const result = parseFile(yaml, 'test.yaml');
    const role = result.resources[0] as import('../src/parser/types').Role;
    expect(role.rules).toEqual([]);
  });

  it('handles empty subjects array in RoleBinding', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: empty-binding
  namespace: default
subjects: []
roleRef:
  kind: Role
  name: some-role
  apiGroup: rbac.authorization.k8s.io
`;
    const result = parseFile(yaml, 'test.yaml');
    const binding = result.resources[0] as import('../src/parser/types').RoleBinding;
    expect(binding.subjects).toEqual([]);
  });

  it('captures YAML parse errors', () => {
    const yaml = `
: invalid yaml: [unclosed bracket
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0].file).toBe('test.yaml');
  });

  it('parses automountServiceAccountToken: true', () => {
    const yaml = `
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-with-token
  namespace: default
automountServiceAccountToken: true
`;
    const result = parseFile(yaml, 'test.yaml');
    const sa = result.resources[0] as import('../src/parser/types').ServiceAccount;
    expect(sa.automountServiceAccountToken).toBe(true);
  });

  it('handles null document in multi-doc stream', () => {
    const yaml = `---
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa-one
  namespace: default
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.errors).toHaveLength(0);
  });

  it('records source file path', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: my-role
  namespace: default
rules: []
`;
    const result = parseFile(yaml, '/path/to/role.yaml');
    const role = result.resources[0] as import('../src/parser/types').Role;
    expect(role.sourceFile).toBe('/path/to/role.yaml');
  });

  it('parses resourceNames on PolicyRule', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: specific-role
  namespace: default
rules:
- apiGroups: [""]
  resources: ["configmaps"]
  resourceNames: ["my-config"]
  verbs: ["get"]
`;
    const result = parseFile(yaml, 'test.yaml');
    const role = result.resources[0] as import('../src/parser/types').Role;
    expect(role.rules[0].resourceNames).toEqual(['my-config']);
  });

  it('parses ClusterRoleBinding', () => {
    const yaml = `
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: admin-binding
subjects:
- kind: ServiceAccount
  name: admin-sa
  namespace: kube-system
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources[0].kind).toBe('ClusterRoleBinding');
    const binding = result.resources[0] as import('../src/parser/types').RoleBinding;
    expect(binding.roleRef.name).toBe('cluster-admin');
  });
});

describe('AuthorizationPolicy parsing', () => {
  it('parses a basic AuthorizationPolicy', () => {
    const yaml = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: my-policy
  namespace: default
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/default/sa/app"]
        namespaces: ["default"]
    to:
    - operation:
        methods: ["GET"]
        paths: ["/api/*"]
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('AuthorizationPolicy');
    const policy = result.resources[0] as import('../src/parser/types').AuthorizationPolicy;
    expect(policy.metadata.name).toBe('my-policy');
    expect(policy.spec.action).toBe('ALLOW');
    expect(policy.spec.rules).toHaveLength(1);
    expect(policy.spec.rules![0].from).toBeDefined();
    expect(policy.spec.rules![0].from![0].source.principals).toEqual(['cluster.local/ns/default/sa/app']);
    expect(policy.spec.rules![0].to![0].operation.methods).toEqual(['GET']);
  });

  it('parses AuthorizationPolicy with no rules (allow-all)', () => {
    const yaml = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: allow-all
  namespace: default
spec:
  action: ALLOW
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('AuthorizationPolicy');
    const policy = result.resources[0] as import('../src/parser/types').AuthorizationPolicy;
    expect(policy.metadata.name).toBe('allow-all');
    expect(policy.spec.action).toBe('ALLOW');
    expect(policy.spec.rules).toBeUndefined();
  });

  it('parses AuthorizationPolicy with wildcard principal', () => {
    const yaml = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: wildcard-principal
  namespace: default
spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals: ["*"]
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('AuthorizationPolicy');
    const policy = result.resources[0] as import('../src/parser/types').AuthorizationPolicy;
    expect(policy.metadata.name).toBe('wildcard-principal');
    expect(policy.spec.action).toBe('ALLOW');
    expect(policy.spec.rules![0].from![0].source.principals).toEqual(['*']);
  });

  it('parses AuthorizationPolicy with wildcard method', () => {
    const yaml = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: wildcard-method
  namespace: default
spec:
  action: ALLOW
  rules:
  - to:
    - operation:
        methods: ["*"]
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('AuthorizationPolicy');
    const policy = result.resources[0] as import('../src/parser/types').AuthorizationPolicy;
    expect(policy.metadata.name).toBe('wildcard-method');
    expect(policy.spec.action).toBe('ALLOW');
    expect(policy.spec.rules![0].to![0].operation.methods).toEqual(['*']);
  });

  it('parses AuthorizationPolicy with DENY action', () => {
    const yaml = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: deny-policy
  namespace: production
spec:
  action: DENY
  rules:
  - from:
    - source:
        principals: ["cluster.local/ns/untrusted/sa/bad-actor"]
    to:
    - operation:
        methods: ["POST", "DELETE"]
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('AuthorizationPolicy');
    const policy = result.resources[0] as import('../src/parser/types').AuthorizationPolicy;
    expect(policy.metadata.name).toBe('deny-policy');
    expect(policy.spec.action).toBe('DENY');
    expect(policy.spec.rules).toHaveLength(1);
    expect(policy.spec.rules![0].from![0].source.principals).toEqual(['cluster.local/ns/untrusted/sa/bad-actor']);
    expect(policy.spec.rules![0].to![0].operation.methods).toEqual(['POST', 'DELETE']);
  });

  it('handles AuthorizationPolicy with missing spec gracefully', () => {
    const yaml = `
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: no-spec
  namespace: default
`;
    const result = parseFile(yaml, 'test.yaml');
    expect(result.resources).toHaveLength(1);
    expect(result.resources[0].kind).toBe('AuthorizationPolicy');
    const policy = result.resources[0] as import('../src/parser/types').AuthorizationPolicy;
    expect(policy.metadata.name).toBe('no-spec');
    expect(policy.spec).toBeDefined();
    expect(policy.spec.action).toBeUndefined();
    expect(policy.spec.rules).toBeUndefined();
  });
});
