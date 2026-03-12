import * as yaml from 'js-yaml';
import type { Violation, ResourceGraph } from '../rules/types';
import type { Role, RoleBinding, ServiceAccount, PolicyRule } from '../parser/types';
import type { FixSuggestion, FixLang } from './types';
import { WRITE_VERBS } from '../rules/utils';

type RuleFixFn = (
  violation: Violation,
  graph: ResourceGraph,
  lang: FixLang,
) => FixSuggestion | null;

function findBinding(resource: string, graph: ResourceGraph): RoleBinding | undefined {
  const parts = resource.split('/');
  const kind = parts[0];
  const name = parts[parts.length - 1];
  if (kind === 'ClusterRoleBinding') {
    return graph.clusterRoleBindings.find(b => b.metadata.name === name);
  }
  if (kind === 'RoleBinding') {
    return graph.roleBindings.find(b => b.metadata.name === name);
  }
  return undefined;
}

function removeVerbFromRules(rules: PolicyRule[], verb: string): string {
  const patched = rules.map(r => ({
    ...r,
    verbs: r.verbs.filter(v => v !== verb && v !== '*'),
  }));
  return yaml.dump({ rules: patched }, { lineWidth: -1, indent: 2 }).trim();
}

function removeResourceFromRules(rules: PolicyRule[], resource: string): string {
  const patched = rules.map(r => ({
    ...r,
    resources: r.resources.filter(res => res !== resource),
  })).filter(r => r.resources.length > 0);
  return yaml.dump({ rules: patched }, { lineWidth: -1, indent: 2 }).trim();
}

function restrictVerbsToReadOnly(rules: PolicyRule[], targetResource?: string): string {
  const readOnly = ['get', 'list', 'watch'];
  const patched = rules.map(r => {
    if (targetResource && !r.resources.includes(targetResource) && !r.resources.includes('*')) return r;
    return { ...r, verbs: r.verbs.filter(v => readOnly.includes(v)) };
  }).filter(r => r.verbs.length > 0);
  return yaml.dump({ rules: patched }, { lineWidth: -1, indent: 2 }).trim();
}

function findRole(resource: string, graph: ResourceGraph): Role | undefined {
  // resource is like "ClusterRole/name" or "Role/ns/name" or "Role/name"
  const parts = resource.split('/');
  const kind = parts[0];
  const name = parts[parts.length - 1];
  const ns = parts.length === 3 ? parts[1] : parts.length === 2 ? undefined : undefined;

  if (kind === 'ClusterRole') return graph.clusterRoles.get(name);
  if (kind === 'Role') {
    if (ns) return graph.roles.get(`${ns}/${name}`);
    // Search by name if ns unknown
    for (const [key, role] of graph.roles) {
      if (role.metadata.name === name) return role;
    }
  }
  return undefined;
}

function findServiceAccount(resource: string, graph: ResourceGraph): ServiceAccount | undefined {
  // resource format: "ServiceAccount/ns/name" or "ServiceAccount/name"
  const parts = resource.split('/');
  if (parts[0] !== 'ServiceAccount') return undefined;
  const name = parts[parts.length - 1];
  const ns = parts.length === 3 ? parts[1] : undefined;
  if (ns) return graph.serviceAccounts.get(`${ns}/${name}`);
  // Search by name if ns unknown
  for (const [, sa] of graph.serviceAccounts) {
    if (sa.metadata.name === name) return sa;
  }
  return undefined;
}

function patchRules(rules: PolicyRule[], patcher: (r: PolicyRule) => PolicyRule): string {
  const patched = rules.map(patcher);
  return yaml.dump({ rules: patched }, { lineWidth: -1, indent: 2 }).trim();
}

const EXPLANATIONS: Record<string, Record<FixLang, string>> = {
  RB1001: {
    en: 'Replace wildcard verb "*" with specific read-only verbs. If write access is needed, explicitly enumerate: create, update, patch, delete.',
    ja: 'ワイルドカード動詞 "*" を特定の読み取り専用動詞に置き換えてください。書き込みアクセスが必要な場合は、create, update, patch, delete を明示的に列挙してください。',
  },
  RB1002: {
    en: 'Replace wildcard resource "*" with only the specific resources this workload requires. Avoid granting access to resources like secrets, nodes, or namespaces unless explicitly needed.',
    ja: 'ワイルドカードリソース "*" を、このワークロードが必要とする特定のリソースのみに置き換えてください。secrets, nodes, namespaces などのリソースへのアクセスは、明示的に必要な場合以外は避けてください。',
  },
  RB2001: {
    en: 'Remove the cluster-admin binding. Create a dedicated ClusterRole with only the minimum required permissions and rebind to it.',
    ja: 'cluster-admin バインディングを削除してください。必要最小限のパーミッションを持つ専用の ClusterRole を作成し、それにバインドし直してください。',
  },
  RB3001: {
    en: 'Restrict secret access to specific named secrets using resourceNames. Remove "list" and "watch" verbs unless the workload needs to enumerate secrets.',
    ja: 'resourceNames を使用して特定のシークレットへのアクセスを制限してください。ワークロードがシークレットを列挙する必要がない限り、"list" と "watch" 動詞を削除してください。',
  },
  RB3002: {
    en: 'Remove write access to secrets. If you must write secrets, restrict to specific named secrets via resourceNames and remove delete/deletecollection.',
    ja: 'シークレットへの書き込みアクセスを削除してください。シークレットへの書き込みが必要な場合は、resourceNames で特定のシークレットに制限し、delete/deletecollection を削除してください。',
  },
  RB4001: {
    en: 'Add automountServiceAccountToken: false to disable automatic token mounting. Mount the token explicitly in pods that need it using a projected volume.',
    ja: 'automountServiceAccountToken: false を追加して、トークンの自動マウントを無効にしてください。トークンが必要な Pod では、projected ボリュームを使って明示的にマウントしてください。',
  },
  RB1003: {
    en: 'Replace wildcard apiGroup "*" with only the specific API groups this role requires, e.g. "" (core), "apps", "batch".',
    ja: 'ワイルドカード apiGroup "*" を、このロールが必要とする特定の API グループ（例: "" (core), "apps", "batch"）のみに置き換えてください。',
  },
  RB1014: {
    en: 'Remove pods/ephemeralcontainers from resources, or restrict verbs to get-only. Ephemeral container injection should only be granted to debugging tools with a clear justification.',
    ja: 'pods/ephemeralcontainers をリソースから削除するか、verb を get のみに制限してください。エフェメラルコンテナの注入は、明確な理由がある場合のみデバッグツールに許可してください。',
  },
  RB2002: {
    en: 'Remove the "escalate" verb. This verb allows privilege escalation and should almost never be granted to workloads.',
    ja: '"escalate" 動詞を削除してください。この動詞は権限昇格を可能にするため、ワークロードに付与すべきではありません。',
  },
  RB2003: {
    en: 'Remove the "bind" verb. This verb allows binding to higher-privileged roles and should be reserved for cluster administrators only.',
    ja: '"bind" 動詞を削除してください。この動詞は高権限ロールへのバインドを許可するため、クラスター管理者のみに予約してください。',
  },
  RB2004: {
    en: 'Restrict Role/ClusterRole write access to read-only (get, list, watch). If RBAC management is required, use a dedicated admission webhook with audit logging.',
    ja: 'Role/ClusterRole の書き込みアクセスを読み取り専用 (get, list, watch) に制限してください。RBAC 管理が必要な場合は、監査ログ付きの専用 admission webhook を使用してください。',
  },
  RB2005: {
    en: 'Restrict RoleBinding/ClusterRoleBinding write access to read-only. The ability to create or modify bindings is equivalent to privilege escalation.',
    ja: 'RoleBinding/ClusterRoleBinding の書き込みアクセスを読み取り専用に制限してください。バインディングの作成・変更は権限昇格と同等です。',
  },
  RB2006: {
    en: 'Remove the "impersonate" verb. Impersonation allows acting as another user/group/SA and should never be granted to workloads.',
    ja: '"impersonate" 動詞を削除してください。なりすましは別のユーザー/グループ/SA として動作することを可能にするため、ワークロードに付与してはなりません。',
  },
  RB2012: {
    en: 'Remove access to certificatesigningrequests/approval. CSR approval allows issuing TLS certificates for any identity. Use a dedicated cert-manager ClusterRole if certificate signing is required.',
    ja: 'certificatesigningrequests/approval へのアクセスを削除してください。CSR 承認は任意のアイデンティティの TLS 証明書発行を可能にします。証明書署名が必要な場合は専用の cert-manager ClusterRole を使用してください。',
  },
  RB3004: {
    en: 'Remove pods/exec from resources. If interactive debugging is needed, consider using ephemeral containers with restricted access, or a dedicated debug namespace.',
    ja: 'pods/exec をリソースから削除してください。インタラクティブなデバッグが必要な場合は、アクセスを制限したエフェメラルコンテナや専用のデバッグ namespace の使用を検討してください。',
  },
  RB3005: {
    en: 'Remove pods/attach from resources. If attaching to containers is necessary, restrict to specific pods using resourceNames.',
    ja: 'pods/attach をリソースから削除してください。コンテナへのアタッチが必要な場合は、resourceNames を使用して特定の Pod に制限してください。',
  },
  RB3010: {
    en: 'Remove pods/portforward from resources. Use a Service or Ingress to expose ports instead of allowing direct port forwarding.',
    ja: 'pods/portforward をリソースから削除してください。直接のポートフォワードを許可する代わりに、Service または Ingress を使用してポートを公開してください。',
  },
  RB3011: {
    en: 'Remove nodes/proxy from resources. Access to the kubelet API should go through the kube-apiserver with proper RBAC, not via the node proxy endpoint.',
    ja: 'nodes/proxy をリソースから削除してください。kubelet API へのアクセスは、node proxy エンドポイント経由ではなく、適切な RBAC を持つ kube-apiserver を通じて行ってください。',
  },
  RB4002: {
    en: 'Create a dedicated ServiceAccount for this workload instead of using the "default" SA. This allows least-privilege permissions without affecting other workloads in the namespace.',
    ja: '"default" SA を使用する代わりに、このワークロード専用の ServiceAccount を作成してください。これにより、namespace 内の他のワークロードに影響を与えずに最小権限を適用できます。',
  },
  RB5001: {
    en: 'Remove system:unauthenticated from the binding subjects. Anonymous users should not have RBAC permissions beyond the built-in public-info-viewer and discovery roles.',
    ja: 'バインディングの subjects から system:unauthenticated を削除してください。匿名ユーザーは、組み込みの public-info-viewer と discovery ロール以外の RBAC 権限を持つべきではありません。',
  },
  RB6002: {
    en: 'Remove system:masters from the binding subjects. This group bypasses RBAC entirely and cannot be revoked at runtime. Use cluster-admin role binding instead for operations that require full access.',
    ja: 'バインディングの subjects から system:masters を削除してください。このグループは RBAC を完全にバイパスし、実行時に取り消すことができません。完全なアクセスが必要な操作には、cluster-admin ロールバインディングを使用してください。',
  },
  RB7001: {
    en: 'Restrict webhook configuration access to read-only (get, list, watch). Write access to admission webhooks allows disabling security controls like OPA Gatekeeper or Kyverno.',
    ja: 'webhook 設定へのアクセスを読み取り専用 (get, list, watch) に制限してください。admission webhook への書き込みアクセスは、OPA Gatekeeper や Kyverno などのセキュリティコントロールの無効化を可能にします。',
  },
  RB3003: {
    en: 'Restrict ConfigMap access to read-only (get, list, watch). Write access to ConfigMaps allows injecting malicious configuration into workloads.',
    ja: 'ConfigMap へのアクセスを読み取り専用 (get, list, watch) に制限してください。ConfigMap への書き込みアクセスは、ワークロードへの悪意のある設定の注入を可能にします。',
  },
  RB3009: {
    en: 'Replace wildcard apiGroup "*" with "" (core) to limit secret access to the core API group only. Wildcard apiGroup grants secret access across all API groups.',
    ja: 'ワイルドカード apiGroup "*" を "" (core) に置き換えて、シークレットへのアクセスを core API グループのみに制限してください。ワイルドカード apiGroup はすべての API グループにわたるシークレットアクセスを付与します。',
  },
  RB3012: {
    en: 'Remove pods/proxy and services/proxy from resources. Use a Service or Ingress to expose endpoints instead of allowing HTTP proxying through kube-apiserver.',
    ja: 'pods/proxy と services/proxy をリソースから削除してください。kube-apiserver 経由の HTTP プロキシを許可する代わりに、Service または Ingress を使用してエンドポイントを公開してください。',
  },
  RB5002: {
    en: 'Remove system:anonymous from the binding subjects. The anonymous user should have no RBAC permissions whatsoever.',
    ja: 'バインディングの subjects から system:anonymous を削除してください。匿名ユーザーはいかなる RBAC 権限も持つべきではありません。',
  },
  RB5007: {
    en: 'Remove system:authenticated from the binding subjects. Granting permissions to all authenticated users is overly broad — use specific users, groups, or ServiceAccounts instead.',
    ja: 'バインディングの subjects から system:authenticated を削除してください。すべての認証済みユーザーに権限を付与することは過度に広範です。代わりに特定のユーザー、グループ、または ServiceAccount を使用してください。',
  },
  RB5008: {
    en: 'Restrict lease access to read-only (get, list, watch). Write access to coordination.k8s.io/leases can disrupt leader election for control plane components.',
    ja: 'lease へのアクセスを読み取り専用 (get, list, watch) に制限してください。coordination.k8s.io/leases への書き込みアクセスは、コントロールプレーンコンポーネントのリーダー選挙を妨害する可能性があります。',
  },
  RB6001: {
    en: 'Create a ServiceAccount in the same namespace as the RoleBinding instead of referencing a ServiceAccount from a different namespace. Cross-namespace SA references indicate a design issue.',
    ja: 'RoleBinding と同じ namespace に ServiceAccount を作成し、別の namespace の ServiceAccount を参照しないようにしてください。クロス namespace の SA 参照は設計上の問題を示しています。',
  },
  RB8001: {
    en: 'Restrict CustomResourceDefinition access to read-only (get, list, watch). CRD write access allows extending the Kubernetes API, potentially introducing new attack vectors.',
    ja: 'CustomResourceDefinition へのアクセスを読み取り専用 (get, list, watch) に制限してください。CRD への書き込みアクセスは Kubernetes API の拡張を可能にし、新たな攻撃ベクターを導入する可能性があります。',
  },
  RB8002: {
    en: 'Restrict DaemonSet access to read-only (get, list, watch). Write access allows scheduling containers on every node, which can be used to run privileged workloads cluster-wide.',
    ja: 'DaemonSet へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスはすべてのノードでコンテナをスケジューリングすることを可能にし、クラスター全体で特権ワークロードを実行するために使用できます。',
  },
  RB8003: {
    en: 'Restrict PriorityClass access to read-only (get, list, watch). Write access allows creating high-priority classes that can evict system-critical pods from nodes.',
    ja: 'PriorityClass へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、ノードからシステムクリティカルな Pod を退避させる可能性がある高優先度クラスの作成を可能にします。',
  },
  RB8004: {
    en: 'Restrict batch/jobs and cronjobs access to read-only (get, list, watch). Write access allows creating resource-intensive jobs for data exfiltration or resource exhaustion.',
    ja: 'batch/jobs および cronjobs へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、データ漏洩やリソース枯渇のための高負荷ジョブの作成を可能にします。',
  },
  RB8005: {
    en: 'Restrict StatefulSet access to read-only (get, list, watch). Write access allows creating persistent workloads with stable storage and network identity that are harder to clean up.',
    ja: 'StatefulSet へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、安定したストレージとネットワーク ID を持つ永続的なワークロードの作成を可能にします。',
  },
  RB8006: {
    en: 'Restrict HorizontalPodAutoscaler access to read-only (get, list, watch). Write access allows scaling workloads to zero (causing downtime) or to very high replica counts (causing resource exhaustion).',
    ja: 'HorizontalPodAutoscaler へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、ワークロードをゼロにスケールダウン（ダウンタイム発生）または非常に高いレプリカ数へスケールアップ（リソース枯渇）することを可能にします。',
  },
  RB7002: {
    en: 'Restrict RuntimeClass access to read-only (get, list, watch). Write access allows switching container runtimes to less-secure handlers, bypassing sandbox isolation (gVisor, Kata Containers).',
    ja: 'RuntimeClass へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、コンテナランタイムをセキュリティの低いハンドラに切り替え、サンドボックス分離（gVisor, Kata Containers）をバイパスすることを可能にします。',
  },
  RB1004: {
    en: 'Separate create and delete into distinct roles. Combining create+delete in one role allows an attacker to cycle resources (delete then recreate with malicious spec).',
    ja: 'create と delete を別々のロールに分離してください。create+delete を同一ロールに組み合わせると、攻撃者がリソースをサイクル（削除して悪意のある spec で再作成）することが可能になります。',
  },
  RB1005: {
    en: 'Remove "patch" or "update" to limit write access. Combining both allows fine-grained and full-field updates. If both are needed, restrict to specific resources via resourceNames.',
    ja: '"patch" または "update" を削除して書き込みアクセスを制限してください。両方の組み合わせは細粒度と全フィールド更新を可能にします。両方必要な場合は、resourceNames で特定のリソースに制限してください。',
  },
  RB1006: {
    en: 'Restrict ClusterRole to specific resources instead of wildcard "*". A ClusterRole with write access to all core resources is equivalent to cluster-admin.',
    ja: 'ClusterRole のリソースをワイルドカード "*" から特定のリソースに制限してください。すべての core リソースへの書き込みアクセスを持つ ClusterRole は cluster-admin と同等です。',
  },
  RB1009: {
    en: 'Restrict verbs on nodes to read-only (get, list, watch). Wildcard verbs on nodes allow modifying node taints, labels, and conditions — enabling workload scheduling manipulation.',
    ja: 'ノードへの動詞を読み取り専用 (get, list, watch) に制限してください。ノードへのワイルドカード動詞は、ノードのテイント、ラベル、コンディションの変更を許可し、ワークロードスケジューリングの操作を可能にします。',
  },
  RB1010: {
    en: 'Restrict verbs on namespaces to read-only (get, list, watch). Wildcard verbs on namespaces allow creating or deleting namespaces, potentially hiding workloads from monitoring.',
    ja: 'namespace への動詞を読み取り専用 (get, list, watch) に制限してください。namespace へのワイルドカード動詞は、namespace の作成・削除を許可し、監視からワークロードを隠す可能性があります。',
  },
  RB1011: {
    en: 'Remove "deletecollection" verb. Bulk deletion of resources is rarely needed and can cause accidental or malicious mass data loss.',
    ja: '"deletecollection" 動詞を削除してください。リソースの一括削除はほとんど必要なく、偶発的または悪意のある大規模データ損失を引き起こす可能性があります。',
  },
  RB2007: {
    en: 'Restrict tokenreviews/subjectaccessreviews to read-only or remove entirely. These resources allow verifying tokens and checking permissions — useful for auth bypass reconnaissance.',
    ja: 'tokenreviews/subjectaccessreviews を読み取り専用に制限するか、完全に削除してください。これらのリソースはトークンの検証と権限チェックを可能にし、認証バイパスの偵察に使用される可能性があります。',
  },
  RB2011: {
    en: 'Restrict ValidatingAdmissionPolicy access to read-only (get, list, watch). Write access allows modifying or disabling admission validation rules cluster-wide.',
    ja: 'ValidatingAdmissionPolicy へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、クラスター全体での admission 検証ルールの変更または無効化を可能にします。',
  },
  RB3006: {
    en: 'Remove pods/log from resources if log access is not required. Pod logs can contain sensitive data including secrets, tokens, and application credentials printed at startup.',
    ja: 'ログアクセスが必要でない場合は、pods/log をリソースから削除してください。Pod ログには、起動時に出力されるシークレット、トークン、アプリケーション資格情報などの機密データが含まれる可能性があります。',
  },
  RB3007: {
    en: 'Remove etcd/etcdclusters from resources. Direct etcd access bypasses all Kubernetes RBAC and exposes the entire cluster state including all secrets.',
    ja: 'etcd/etcdclusters をリソースから削除してください。etcd への直接アクセスはすべての Kubernetes RBAC をバイパスし、すべてのシークレットを含むクラスター状態全体を公開します。',
  },
  RB3008: {
    en: 'Restrict PersistentVolume/PVC access to read-only (get, list, watch). Write access allows mounting volumes with sensitive data or creating volumes for data persistence after compromise.',
    ja: 'PersistentVolume/PVC へのアクセスを読み取り専用 (get, list, watch) に制限してください。書き込みアクセスは、機密データを含むボリュームのマウントや、侵害後のデータ永続化のためのボリューム作成を可能にします。',
  },
  IS1002: {
    en: 'Replace wildcard principal "*" with specific service account principals. Use "cluster.local/ns/<namespace>/sa/<serviceaccount>" format to restrict to specific workloads.',
    ja: 'ワイルドカードプリンシパル "*" を特定のサービスアカウントプリンシパルに置き換えてください。特定のワークロードに制限するには "cluster.local/ns/<namespace>/sa/<serviceaccount>" 形式を使用してください。',
  },
  IS1003: {
    en: 'Replace wildcard HTTP method "*" with specific methods (GET, POST, etc.). Only grant the HTTP methods that the target workload actually needs.',
    ja: 'ワイルドカード HTTP メソッド "*" を特定のメソッド（GET, POST など）に置き換えてください。対象ワークロードが実際に必要とする HTTP メソッドのみを許可してください。',
  },
  RB4003: {
    en: 'Replace the broad ClusterRole with a dedicated ClusterRole that grants only the specific permissions this ServiceAccount requires.',
    ja: '広範な ClusterRole を、この ServiceAccount が必要とする特定の権限のみを付与する専用の ClusterRole に置き換えてください。',
  },
  RB4004: {
    en: 'Add a namespace to the ServiceAccount metadata. A ServiceAccount without a namespace may be applied to unintended namespaces.',
    ja: 'ServiceAccount のメタデータに namespace を追加してください。namespace のない ServiceAccount は意図しない namespace に適用される可能性があります。',
  },
  RB4005: {
    en: 'Remove this unused ServiceAccount, or create a RoleBinding to grant it appropriate permissions. Orphaned ServiceAccounts accumulate over time and increase the attack surface.',
    ja: 'この未使用の ServiceAccount を削除するか、適切な権限を付与する RoleBinding を作成してください。孤立した ServiceAccount は時間とともに蓄積され、攻撃対象を拡大します。',
  },
  RB4006: {
    en: 'Consolidate this ServiceAccount into a single namespace. Cross-namespace bindings indicate design issues — create namespace-specific ServiceAccounts instead.',
    ja: 'この ServiceAccount を単一の namespace に集約してください。クロス namespace バインディングは設計上の問題を示しています。代わりに namespace 固有の ServiceAccount を作成してください。',
  },
  RB4007: {
    en: 'Add a description annotation to document the purpose of this ServiceAccount. Use "description" or "kubectl.kubernetes.io/description" annotation.',
    ja: 'この ServiceAccount の目的を文書化するために description アノテーションを追加してください。"description" または "kubectl.kubernetes.io/description" アノテーションを使用してください。',
  },
  RB4008: {
    en: 'Set automountServiceAccountToken: false and use projected volumes with explicit token expiry if token access is needed.',
    ja: 'automountServiceAccountToken: false を設定し、トークンアクセスが必要な場合は有効期限付きの projected ボリュームを使用してください。',
  },
  RB4009: {
    en: 'Remove the "create" verb from the pods permission in the referenced role, or restrict to a specific namespace. ServiceAccounts that can create pods can mount arbitrary tokens via the pod spec.',
    ja: '参照されたロールの pods 権限から "create" 動詞を削除するか、特定の namespace に制限してください。Pod を作成できる ServiceAccount は、Pod spec 経由で任意のトークンをマウントできます。',
  },
  RB9001: {
    en: 'Remove write access to nodes/status. Only kubelet itself should update node status. Any other write access allows faking node conditions and misleading the scheduler.',
    ja: 'nodes/status への書き込みアクセスを削除してください。ノードステータスを更新できるのは kubelet 自身のみです。その他の書き込みアクセスはノードコンディションの偽装とスケジューラの誤誘導を可能にします。',
  },
  RB9002: {
    en: 'Remove write access to pods/status. Only the pod controller should update pod status. Falsified pod status can cause load balancers to route traffic to unhealthy pods.',
    ja: 'pods/status への書き込みアクセスを削除してください。Pod ステータスを更新できるのは Pod コントローラのみです。偽装された Pod ステータスはロードバランサが不健全な Pod にトラフィックをルーティングする原因になります。',
  },
  RB9003: {
    en: 'Remove write access to resourcequotas. ResourceQuota management should be restricted to cluster administrators. Write access allows removing limits and exhausting cluster resources.',
    ja: 'resourcequotas への書き込みアクセスを削除してください。ResourceQuota の管理はクラスター管理者に制限すべきです。書き込みアクセスは制限の削除とクラスターリソースの枯渇を可能にします。',
  },
  RB9004: {
    en: 'Remove write access to limitranges. LimitRange management should be restricted to namespace administrators. Write access allows removing default resource limits from containers.',
    ja: 'limitranges への書き込みアクセスを削除してください。LimitRange の管理は namespace 管理者に制限すべきです。書き込みアクセスはコンテナのデフォルトリソース制限の削除を可能にします。',
  },
};

const RB1001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const patch = patchRules(role.rules, (r) => ({
    ...r,
    verbs: r.verbs.includes('*') ? ['get', 'list', 'watch'] : r.verbs,
  }));

  return {
    violation,
    ruleId: 'RB1001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB1001[lang],
    yamlPatch: patch,
    autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB1002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const patch = patchRules(role.rules, (r) => ({
    ...r,
    resources: r.resources.includes('*') ? ['pods'] : r.resources,
  }));

  return {
    violation,
    ruleId: 'RB1002',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB1002[lang],
    yamlPatch: `# TODO: replace 'pods' with the actual resources this workload requires\n${patch}`,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB2001Fix: RuleFixFn = (violation, graph, lang) => {
  const parts = violation.resource.split('/');
  const bindingName = parts[parts.length - 1];
  const restrictedName = `${bindingName.replace('-binding', '')}-restricted`;

  const suggestedRole = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${restrictedName}
rules:
  [] # TODO: add only the permissions this workload requires`;

  const suggestedBinding = `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${bindingName}
subjects: # keep existing subjects
roleRef:
  kind: ClusterRole
  name: ${restrictedName}
  apiGroup: rbac.authorization.k8s.io`;

  return {
    violation,
    ruleId: 'RB2001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB2001[lang],
    yamlPatch: `${suggestedRole}\n---\n${suggestedBinding}`,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

const RB3001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const patch = patchRules(role.rules, (r) => {
    if (!r.resources.includes('secrets') && !r.resources.includes('*')) return r;
    return {
      ...r,
      verbs: r.verbs.filter(v => v !== 'list' && v !== 'watch' && v !== '*'),
      resourceNames: r.resourceNames ?? ['# TODO: list specific secret names here'],
    };
  });

  return {
    violation,
    ruleId: 'RB3001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB3001[lang],
    yamlPatch: patch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB3002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;

  const allWriteVerbs = [...WRITE_VERBS, '*'];
  const patch = patchRules(role.rules, (r) => {
    if (!r.resources.includes('secrets') && !r.resources.includes('*')) return r;
    return {
      ...r,
      verbs: r.verbs.filter(v => !allWriteVerbs.includes(v)),
      resourceNames: r.resourceNames ?? ['# TODO: specify secret names if read access is required'],
    };
  });

  return {
    violation,
    ruleId: 'RB3002',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB3002[lang],
    yamlPatch: patch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

const RB4001Fix: RuleFixFn = (violation, graph, lang) => {
  const saName = violation.resource.replace('ServiceAccount/', '').split('/').pop() ?? '';
  const patch = `automountServiceAccountToken: false`;

  return {
    violation,
    ruleId: 'RB4001',
    source: 'rule-based',
    explanation: EXPLANATIONS.RB4001[lang],
    yamlPatch: patch,
    autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

// ── RB1003: wildcard apiGroups ────────────────────────────────────────────────
const RB1003Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => ({
    ...r,
    apiGroups: r.apiGroups.includes('*') ? ['# TODO: replace with specific apiGroups e.g. "", "apps", "batch"'] : r.apiGroups,
  }));
  return {
    violation, ruleId: 'RB1003', source: 'rule-based',
    explanation: EXPLANATIONS.RB1003[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1014: pods/ephemeralcontainers write ────────────────────────────────────
const RB1014Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'pods/ephemeralcontainers');
  return {
    violation, ruleId: 'RB1014', source: 'rule-based',
    explanation: EXPLANATIONS.RB1014[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2002: escalate verb ─────────────────────────────────────────────────────
const RB2002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeVerbFromRules(role.rules, 'escalate');
  return {
    violation, ruleId: 'RB2002', source: 'rule-based',
    explanation: EXPLANATIONS.RB2002[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2003: bind verb ─────────────────────────────────────────────────────────
const RB2003Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeVerbFromRules(role.rules, 'bind');
  return {
    violation, ruleId: 'RB2003', source: 'rule-based',
    explanation: EXPLANATIONS.RB2003[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2004: RBAC role write ───────────────────────────────────────────────────
const RB2004Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules);
  return {
    violation, ruleId: 'RB2004', source: 'rule-based',
    explanation: EXPLANATIONS.RB2004[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2005: RoleBinding write ─────────────────────────────────────────────────
const RB2005Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules);
  return {
    violation, ruleId: 'RB2005', source: 'rule-based',
    explanation: EXPLANATIONS.RB2005[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2006: impersonate verb ──────────────────────────────────────────────────
const RB2006Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeVerbFromRules(role.rules, 'impersonate');
  return {
    violation, ruleId: 'RB2006', source: 'rule-based',
    explanation: EXPLANATIONS.RB2006[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2012: CSR approval ──────────────────────────────────────────────────────
const RB2012Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'certificatesigningrequests/approval');
  return {
    violation, ruleId: 'RB2012', source: 'rule-based',
    explanation: EXPLANATIONS.RB2012[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3004: pods/exec ─────────────────────────────────────────────────────────
const RB3004Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'pods/exec');
  return {
    violation, ruleId: 'RB3004', source: 'rule-based',
    explanation: EXPLANATIONS.RB3004[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3005: pods/attach ───────────────────────────────────────────────────────
const RB3005Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'pods/attach');
  return {
    violation, ruleId: 'RB3005', source: 'rule-based',
    explanation: EXPLANATIONS.RB3005[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3010: pods/portforward ──────────────────────────────────────────────────
const RB3010Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'pods/portforward');
  return {
    violation, ruleId: 'RB3010', source: 'rule-based',
    explanation: EXPLANATIONS.RB3010[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3011: nodes/proxy ───────────────────────────────────────────────────────
const RB3011Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'nodes/proxy');
  return {
    violation, ruleId: 'RB3011', source: 'rule-based',
    explanation: EXPLANATIONS.RB3011[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB4002: default ServiceAccount ───────────────────────────────────────────
const RB4002Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  const bindingName = violation.resource.split('/').pop() ?? 'my-binding';
  const ns = binding?.metadata.namespace ?? 'default';
  const workloadName = bindingName.replace(/-binding$/, '').replace(/-cluster-binding$/, '');
  const patch = `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${workloadName}
  namespace: ${ns}
  annotations:
    # TODO: add description of what this SA is used for
automountServiceAccountToken: false
---
# Update the binding to reference the new ServiceAccount:
# subjects:
# - kind: ServiceAccount
#   name: ${workloadName}
#   namespace: ${ns}`;
  return {
    violation, ruleId: 'RB4002', source: 'rule-based',
    explanation: EXPLANATIONS.RB4002[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB5001: system:unauthenticated binding ────────────────────────────────────
const RB5001Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  if (!binding) return null;
  const safeSubjects = binding.subjects.filter(
    s => s.name !== 'system:unauthenticated',
  );
  const patch = safeSubjects.length > 0
    ? yaml.dump({ subjects: safeSubjects }, { lineWidth: -1, indent: 2 }).trim()
    : '# WARNING: removing system:unauthenticated leaves no subjects — delete this binding if it is no longer needed';
  return {
    violation, ruleId: 'RB5001', source: 'rule-based',
    explanation: EXPLANATIONS.RB5001[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB6002: system:masters binding ───────────────────────────────────────────
const RB6002Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  if (!binding) return null;
  const safeSubjects = binding.subjects.filter(
    s => !(s.kind === 'Group' && s.name === 'system:masters'),
  );
  const bindingKind = binding.kind;
  const bindingName = binding.metadata.name;
  const patch = `# Replace system:masters with a cluster-admin ClusterRoleBinding:
apiVersion: rbac.authorization.k8s.io/v1
kind: ${bindingKind}
metadata:
  name: ${bindingName}
subjects:
${safeSubjects.length > 0
    ? safeSubjects.map(s => `- kind: ${s.kind}\n  name: ${s.name}${s.namespace ? `\n  namespace: ${s.namespace}` : ''}`).join('\n')
    : '  [] # TODO: add appropriate subjects'}
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io`;
  return {
    violation, ruleId: 'RB6002', source: 'rule-based',
    explanation: EXPLANATIONS.RB6002[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB3003: configmaps write ──────────────────────────────────────────────────
const RB3003Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    if (!r.resources.includes('configmaps') && !r.resources.includes('*')) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB3003', source: 'rule-based',
    explanation: EXPLANATIONS.RB3003[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3009: secrets via wildcard apiGroup ─────────────────────────────────────
const RB3009Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    if (!r.apiGroups.includes('*')) return r;
    const targetsSecrets = r.resources.includes('secrets') || r.resources.includes('*');
    if (!targetsSecrets) return r;
    return { ...r, apiGroups: r.apiGroups.map(g => (g === '*' ? '' : g)) };
  });
  return {
    violation, ruleId: 'RB3009', source: 'rule-based',
    explanation: EXPLANATIONS.RB3009[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3012: pods/proxy + services/proxy ───────────────────────────────────────
const RB3012Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  // Remove both proxy subresources
  let rules = role.rules;
  for (const res of ['pods/proxy', 'services/proxy']) {
    rules = rules.map(r => ({
      ...r,
      resources: r.resources.filter(resource => resource !== res),
    })).filter(r => r.resources.length > 0);
  }
  const patch = yaml.dump({ rules }, { lineWidth: -1, indent: 2 }).trim();
  return {
    violation, ruleId: 'RB3012', source: 'rule-based',
    explanation: EXPLANATIONS.RB3012[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB5002: system:anonymous binding ─────────────────────────────────────────
const RB5002Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  if (!binding) return null;
  const safeSubjects = binding.subjects.filter(s => s.name !== 'system:anonymous');
  const patch = safeSubjects.length > 0
    ? yaml.dump({ subjects: safeSubjects }, { lineWidth: -1, indent: 2 }).trim()
    : '# WARNING: removing system:anonymous leaves no subjects — delete this binding';
  return {
    violation, ruleId: 'RB5002', source: 'rule-based',
    explanation: EXPLANATIONS.RB5002[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB5007: system:authenticated binding ──────────────────────────────────────
const RB5007Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  if (!binding) return null;
  const safeSubjects = binding.subjects.filter(
    s => !(s.kind === 'Group' && s.name === 'system:authenticated'),
  );
  const patch = safeSubjects.length > 0
    ? yaml.dump({ subjects: safeSubjects }, { lineWidth: -1, indent: 2 }).trim()
    : `# Replace system:authenticated with specific subjects, e.g.:
subjects:
- kind: ServiceAccount
  name: your-service-account
  namespace: your-namespace`;
  return {
    violation, ruleId: 'RB5007', source: 'rule-based',
    explanation: EXPLANATIONS.RB5007[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB5008: leases write ──────────────────────────────────────────────────────
const RB5008Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const coordGroup = r.apiGroups.includes('coordination.k8s.io') || r.apiGroups.includes('*');
    const targetsLeases = r.resources.includes('leases') || r.resources.includes('*');
    if (!coordGroup || !targetsLeases) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB5008', source: 'rule-based',
    explanation: EXPLANATIONS.RB5008[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB6001: cross-namespace ServiceAccount ────────────────────────────────────
const RB6001Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  if (!binding) return null;
  const bindingNs = binding.metadata.namespace ?? 'default';
  // Find the cross-namespace subjects
  const crossNsSubjects = binding.subjects.filter(
    s => s.kind === 'ServiceAccount' && s.namespace && s.namespace !== bindingNs,
  );
  if (crossNsSubjects.length === 0) return null;
  const patch = crossNsSubjects.map(s => `apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${s.name}
  namespace: ${bindingNs}
  # TODO: migrate this SA from namespace '${s.namespace}' to '${bindingNs}'
automountServiceAccountToken: false`).join('\n---\n');
  return {
    violation, ruleId: 'RB6001', source: 'rule-based',
    explanation: EXPLANATIONS.RB6001[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB8001: CRD write ─────────────────────────────────────────────────────────
const RB8001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const apiExtGroup = r.apiGroups.includes('apiextensions.k8s.io') || r.apiGroups.includes('*');
    const targetsCRD = r.resources.includes('customresourcedefinitions') || r.resources.includes('*');
    if (!apiExtGroup || !targetsCRD) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB8001', source: 'rule-based',
    explanation: EXPLANATIONS.RB8001[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB8002: daemonsets write ──────────────────────────────────────────────────
const RB8002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const appsGroup = r.apiGroups.includes('apps') || r.apiGroups.includes('*');
    const targetsDaemonSet = r.resources.includes('daemonsets') || r.resources.includes('*');
    if (!appsGroup || !targetsDaemonSet) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB8002', source: 'rule-based',
    explanation: EXPLANATIONS.RB8002[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB8003: priorityclasses write ─────────────────────────────────────────────
const RB8003Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const schedGroup = r.apiGroups.includes('scheduling.k8s.io') || r.apiGroups.includes('*');
    const targetsPriority = r.resources.includes('priorityclasses') || r.resources.includes('*');
    if (!schedGroup || !targetsPriority) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB8003', source: 'rule-based',
    explanation: EXPLANATIONS.RB8003[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1004: create + delete combined ─────────────────────────────────────────
const RB1004Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeVerbFromRules(role.rules, 'delete');
  return {
    violation, ruleId: 'RB1004', source: 'rule-based',
    explanation: EXPLANATIONS.RB1004[lang],
    yamlPatch: `# Removed 'delete' verb — consider using a separate role for deletion if needed\n${patch}`,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1005: update + patch combined ──────────────────────────────────────────
const RB1005Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeVerbFromRules(role.rules, 'patch');
  return {
    violation, ruleId: 'RB1005', source: 'rule-based',
    explanation: EXPLANATIONS.RB1005[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1006: ClusterRole write to all core resources ───────────────────────────
const RB1006Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules);
  return {
    violation, ruleId: 'RB1006', source: 'rule-based',
    explanation: EXPLANATIONS.RB1006[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1009: * verbs on nodes ──────────────────────────────────────────────────
const RB1009Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules, 'nodes');
  return {
    violation, ruleId: 'RB1009', source: 'rule-based',
    explanation: EXPLANATIONS.RB1009[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1010: * verbs on namespaces ─────────────────────────────────────────────
const RB1010Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules, 'namespaces');
  return {
    violation, ruleId: 'RB1010', source: 'rule-based',
    explanation: EXPLANATIONS.RB1010[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB1011: deletecollection verb ─────────────────────────────────────────────
const RB1011Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeVerbFromRules(role.rules, 'deletecollection');
  return {
    violation, ruleId: 'RB1011', source: 'rule-based',
    explanation: EXPLANATIONS.RB1011[lang],
    yamlPatch: patch, autoApplicable: true,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2007: tokenreviews/subjectaccessreviews ─────────────────────────────────
const RB2007Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const authResources = ['tokenreviews', 'subjectaccessreviews'];
  const patch = patchRules(role.rules, (r) => {
    const targets = authResources.some(res => r.resources.includes(res));
    if (!targets) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB2007', source: 'rule-based',
    explanation: EXPLANATIONS.RB2007[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB2011: ValidatingAdmissionPolicy write ───────────────────────────────────
const RB2011Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const vapResources = ['validatingadmissionpolicies', 'validatingadmissionpolicybindings'];
  const patch = patchRules(role.rules, (r) => {
    const targets = vapResources.some(res => r.resources.includes(res)) || r.resources.includes('*');
    const apiOk = r.apiGroups.includes('admissionregistration.k8s.io') || r.apiGroups.includes('*');
    if (!targets || !apiOk) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB2011', source: 'rule-based',
    explanation: EXPLANATIONS.RB2011[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3006: pods/log ──────────────────────────────────────────────────────────
const RB3006Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'pods/log');
  return {
    violation, ruleId: 'RB3006', source: 'rule-based',
    explanation: EXPLANATIONS.RB3006[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3007: etcd access ───────────────────────────────────────────────────────
const RB3007Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const etcdResources = ['etcd', 'etcdclusters'];
  let rules = role.rules;
  for (const res of etcdResources) {
    rules = rules.map(r => ({
      ...r,
      resources: r.resources.filter(resource => resource !== res),
    })).filter(r => r.resources.length > 0);
  }
  const patch = yaml.dump({ rules }, { lineWidth: -1, indent: 2 }).trim();
  return {
    violation, ruleId: 'RB3007', source: 'rule-based',
    explanation: EXPLANATIONS.RB3007[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB3008: persistentvolumes access ─────────────────────────────────────────
const RB3008Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const pvResources = ['persistentvolumes', 'persistentvolumeclaims', 'volumeattachments'];
  const patch = patchRules(role.rules, (r) => {
    const targets = pvResources.some(res => r.resources.includes(res)) || r.resources.includes('*');
    if (!targets) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB3008', source: 'rule-based',
    explanation: EXPLANATIONS.RB3008[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB8004: batch/jobs write ──────────────────────────────────────────────────
const RB8004Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const batchResources = ['jobs', 'cronjobs'];
  const patch = patchRules(role.rules, (r) => {
    const batchGroup = r.apiGroups.includes('batch') || r.apiGroups.includes('*');
    const targets = batchResources.some(res => r.resources.includes(res)) || r.resources.includes('*');
    if (!batchGroup || !targets) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB8004', source: 'rule-based',
    explanation: EXPLANATIONS.RB8004[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB8005: statefulsets write ────────────────────────────────────────────────
const RB8005Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const appsGroup = r.apiGroups.includes('apps') || r.apiGroups.includes('*');
    const targets = r.resources.includes('statefulsets') || r.resources.includes('*');
    if (!appsGroup || !targets) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB8005', source: 'rule-based',
    explanation: EXPLANATIONS.RB8005[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB8006: horizontalpodautoscalers write ────────────────────────────────────
const RB8006Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const autoscalingGroup = r.apiGroups.includes('autoscaling') || r.apiGroups.includes('*');
    const targets = r.resources.includes('horizontalpodautoscalers') || r.resources.includes('*');
    if (!autoscalingGroup || !targets) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB8006', source: 'rule-based',
    explanation: EXPLANATIONS.RB8006[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB7002: runtimeclasses write ──────────────────────────────────────────────
const RB7002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const nodeGroup = r.apiGroups.includes('node.k8s.io') || r.apiGroups.includes('*');
    const targets = r.resources.includes('runtimeclasses') || r.resources.includes('*');
    if (!nodeGroup || !targets) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  });
  return {
    violation, ruleId: 'RB7002', source: 'rule-based',
    explanation: EXPLANATIONS.RB7002[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB4003: SA bound to broad ClusterRole ────────────────────────────────────
const RB4003Fix: RuleFixFn = (violation, graph, lang) => {
  const binding = findBinding(violation.resource, graph);
  if (!binding) return null;
  const oldRole = binding.roleRef.name;
  const restrictedName = `${oldRole}-restricted`;
  const patch = `# Create a new restricted ClusterRole:
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${restrictedName}
rules:
  [] # TODO: add only the minimum permissions this ServiceAccount requires
---
# Update the binding's roleRef to use the new restricted role:
# roleRef:
#   kind: ClusterRole
#   name: ${restrictedName}
#   apiGroup: rbac.authorization.k8s.io`;
  return {
    violation, ruleId: 'RB4003', source: 'rule-based',
    explanation: EXPLANATIONS.RB4003[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
};

// ── RB4004: SA without namespace ─────────────────────────────────────────────
const RB4004Fix: RuleFixFn = (violation, graph, lang) => {
  const sa = findServiceAccount(violation.resource, graph);
  const saName = violation.resource.split('/').pop() ?? 'my-sa';
  const patch = `metadata:
  name: ${sa?.metadata.name ?? saName}
  namespace: default # TODO: replace with the correct namespace`;
  return {
    violation, ruleId: 'RB4004', source: 'rule-based',
    explanation: EXPLANATIONS.RB4004[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

// ── RB4005: SA with no bindings ───────────────────────────────────────────────
const RB4005Fix: RuleFixFn = (violation, _graph, lang) => {
  const saName = violation.resource.split('/').pop() ?? 'my-sa';
  const patch = `# Option 1: Remove the unused ServiceAccount
# kubectl delete serviceaccount ${saName}

# Option 2: If it IS needed, add a RoleBinding:
# apiVersion: rbac.authorization.k8s.io/v1
# kind: RoleBinding
# metadata:
#   name: ${saName}-binding
#   namespace: default
# subjects:
# - kind: ServiceAccount
#   name: ${saName}
#   namespace: default
# roleRef:
#   kind: Role
#   name: TODO-role-name
#   apiGroup: rbac.authorization.k8s.io`;
  return {
    violation, ruleId: 'RB4005', source: 'rule-based',
    explanation: EXPLANATIONS.RB4005[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

// ── RB4006: SA bound in multiple namespaces ───────────────────────────────────
const RB4006Fix: RuleFixFn = (violation, _graph, lang) => {
  const saName = violation.resource.split('/').pop() ?? 'my-sa';
  const patch = `# Create namespace-specific ServiceAccounts instead of sharing one SA across namespaces:
# For each namespace that needs this SA, create a dedicated SA:
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${saName}
  namespace: namespace-a  # Replace with each specific namespace
  annotations:
    description: "Dedicated SA for namespace-a workloads"
automountServiceAccountToken: false`;
  return {
    violation, ruleId: 'RB4006', source: 'rule-based',
    explanation: EXPLANATIONS.RB4006[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

// ── RB4007: SA without description annotation ─────────────────────────────────
const RB4007Fix: RuleFixFn = (violation, graph, lang) => {
  const sa = findServiceAccount(violation.resource, graph);
  const saName = sa?.metadata.name ?? violation.resource.split('/').pop() ?? 'my-sa';
  const ns = sa?.metadata.namespace ?? 'default';
  const patch = `metadata:
  name: ${saName}
  namespace: ${ns}
  annotations:
    description: "TODO: describe the purpose of this ServiceAccount"`;
  return {
    violation, ruleId: 'RB4007', source: 'rule-based',
    explanation: EXPLANATIONS.RB4007[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

// ── RB4008: SA with explicit automount and no expiry ──────────────────────────
const RB4008Fix: RuleFixFn = (violation, graph, lang) => {
  const sa = findServiceAccount(violation.resource, graph);
  const saName = sa?.metadata.name ?? violation.resource.split('/').pop() ?? 'my-sa';
  const ns = sa?.metadata.namespace ?? 'default';
  const patch = `# Option 1: Disable automounting (recommended — mount explicitly in pods):
automountServiceAccountToken: false

# Option 2: If automounting is needed, add an expiry annotation:
# metadata:
#   name: ${saName}
#   namespace: ${ns}
#   annotations:
#     rbacvet/token-expiry: "3600"  # seconds`;
  return {
    violation, ruleId: 'RB4008', source: 'rule-based',
    explanation: EXPLANATIONS.RB4008[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
};

// ── RB4009: SA can create pods ────────────────────────────────────────────────
const RB4009Fix: RuleFixFn = (violation, graph, lang) => {
  // violation.resource is "ServiceAccount/ns/name" — find the binding to get the role
  const parts = violation.resource.split('/');
  const saName = parts[parts.length - 1];
  const saNs = parts.length >= 3 ? parts[1] : undefined;
  const allBindings = [...graph.roleBindings, ...graph.clusterRoleBindings];
  const binding = allBindings.find(b =>
    b.subjects.some(s => s.kind === 'ServiceAccount' && s.name === saName &&
      (!saNs || s.namespace === saNs))
  );
  if (!binding) {
    const patch = `# Remove 'create' from the pods rule in the Role/ClusterRole bound to this ServiceAccount`;
    return { violation, ruleId: 'RB4009', source: 'rule-based', explanation: EXPLANATIONS.RB4009[lang], yamlPatch: patch, autoApplicable: false, patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 } };
  }
  const role = binding.roleRef.kind === 'ClusterRole'
    ? graph.clusterRoles.get(binding.roleRef.name)
    : (() => {
        const ns = binding.metadata.namespace;
        return graph.roles.get(ns ? `${ns}/${binding.roleRef.name}` : binding.roleRef.name);
      })();
  if (!role) return null;
  const patch = patchRules(role.rules, (r) => {
    const targetsPods = r.resources.includes('pods') || r.resources.includes('*');
    if (!targetsPods) return r;
    return { ...r, verbs: r.verbs.filter(v => v !== 'create') };
  });
  return {
    violation, ruleId: 'RB4009', source: 'rule-based',
    explanation: EXPLANATIONS.RB4009[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: role.sourceFile, startLine: role.sourceLine, endLine: role.sourceLine + 30 },
  };
};

// ── RB9001: nodes/status write ────────────────────────────────────────────────
const RB9001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'nodes/status');
  return {
    violation, ruleId: 'RB9001', source: 'rule-based',
    explanation: EXPLANATIONS.RB9001[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB9002: pods/status write ─────────────────────────────────────────────────
const RB9002Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = removeResourceFromRules(role.rules, 'pods/status');
  return {
    violation, ruleId: 'RB9002', source: 'rule-based',
    explanation: EXPLANATIONS.RB9002[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB9003: resourcequotas write ──────────────────────────────────────────────
const RB9003Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules, 'resourcequotas');
  return {
    violation, ruleId: 'RB9003', source: 'rule-based',
    explanation: EXPLANATIONS.RB9003[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB9004: limitranges write ─────────────────────────────────────────────────
const RB9004Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const patch = restrictVerbsToReadOnly(role.rules, 'limitranges');
  return {
    violation, ruleId: 'RB9004', source: 'rule-based',
    explanation: EXPLANATIONS.RB9004[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

// ── RB7001: admission webhook write ──────────────────────────────────────────
const RB7001Fix: RuleFixFn = (violation, graph, lang) => {
  const role = findRole(violation.resource, graph);
  if (!role) return null;
  const webhookResources = ['validatingwebhookconfigurations', 'mutatingwebhookconfigurations'];
  const patch = patchRules(role.rules, (r) => {
    const targetsWebhook = webhookResources.some(res => r.resources.includes(res)) || r.resources.includes('*');
    if (!targetsWebhook) return r;
    return { ...r, verbs: r.verbs.filter(v => ['get', 'list', 'watch'].includes(v)) };
  }).trim() || yaml.dump({ rules: role.rules }, { lineWidth: -1, indent: 2 }).trim();
  return {
    violation, ruleId: 'RB7001', source: 'rule-based',
    explanation: EXPLANATIONS.RB7001[lang],
    yamlPatch: patch, autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 30 },
  };
};

export const RULE_FIX_MAP = new Map<string, RuleFixFn>([
  ['RB1001', RB1001Fix],
  ['RB1002', RB1002Fix],
  ['RB1003', RB1003Fix],
  ['RB1004', RB1004Fix],
  ['RB1005', RB1005Fix],
  ['RB1006', RB1006Fix],
  ['RB1009', RB1009Fix],
  ['RB1010', RB1010Fix],
  ['RB1011', RB1011Fix],
  ['RB1014', RB1014Fix],
  ['RB2001', RB2001Fix],
  ['RB2002', RB2002Fix],
  ['RB2003', RB2003Fix],
  ['RB2004', RB2004Fix],
  ['RB2005', RB2005Fix],
  ['RB2006', RB2006Fix],
  ['RB2007', RB2007Fix],
  ['RB2011', RB2011Fix],
  ['RB2012', RB2012Fix],
  ['RB3001', RB3001Fix],
  ['RB3002', RB3002Fix],
  ['RB3003', RB3003Fix],
  ['RB3004', RB3004Fix],
  ['RB3005', RB3005Fix],
  ['RB3006', RB3006Fix],
  ['RB3007', RB3007Fix],
  ['RB3008', RB3008Fix],
  ['RB3009', RB3009Fix],
  ['RB3010', RB3010Fix],
  ['RB3011', RB3011Fix],
  ['RB3012', RB3012Fix],
  ['RB4001', RB4001Fix],
  ['RB4002', RB4002Fix],
  ['RB4003', RB4003Fix],
  ['RB4004', RB4004Fix],
  ['RB4005', RB4005Fix],
  ['RB4006', RB4006Fix],
  ['RB4007', RB4007Fix],
  ['RB4008', RB4008Fix],
  ['RB4009', RB4009Fix],
  ['RB5001', RB5001Fix],
  ['RB5002', RB5002Fix],
  ['RB5007', RB5007Fix],
  ['RB5008', RB5008Fix],
  ['RB6001', RB6001Fix],
  ['RB6002', RB6002Fix],
  ['RB7001', RB7001Fix],
  ['RB7002', RB7002Fix],
  ['RB8001', RB8001Fix],
  ['RB8002', RB8002Fix],
  ['RB8003', RB8003Fix],
  ['RB8004', RB8004Fix],
  ['RB8005', RB8005Fix],
  ['RB8006', RB8006Fix],
  ['RB9001', RB9001Fix],
  ['RB9002', RB9002Fix],
  ['RB9003', RB9003Fix],
  ['RB9004', RB9004Fix],
]);

RULE_FIX_MAP.set('IS1002', (violation, _graph, lang) => {
  const name = violation.resource.split('/').pop() ?? 'policy';
  const ns = violation.resource.split('/')[1] ?? 'default';
  const yamlPatch = `spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/${ns}/sa/your-service-account
    to:
    - operation:
        methods: ["GET", "POST"]`;
  return {
    violation,
    ruleId: 'IS1002',
    source: 'rule-based',
    explanation: lang === 'ja'
      ? EXPLANATIONS.IS1002.ja
      : EXPLANATIONS.IS1002.en,
    yamlPatch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
});

RULE_FIX_MAP.set('IS1003', (violation, _graph, lang) => {
  const yamlPatch = `spec:
  action: ALLOW
  rules:
  - to:
    - operation:
        methods: ["GET", "POST"]
        # Replace with the specific HTTP methods this workload needs`;
  return {
    violation,
    ruleId: 'IS1003',
    source: 'rule-based',
    explanation: lang === 'ja'
      ? EXPLANATIONS.IS1003.ja
      : EXPLANATIONS.IS1003.en,
    yamlPatch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 10 },
  };
});

RULE_FIX_MAP.set('IS1001', (violation, _graph, lang) => {
  const name = violation.resource.split('/').pop() ?? 'policy';
  const ns = violation.resource.split('/')[1] ?? 'default';
  const yamlPatch = `spec:
  action: ALLOW
  rules:
  - from:
    - source:
        principals:
        - cluster.local/ns/${ns}/sa/your-service-account
    to:
    - operation:
        methods: ["GET"]`;
  return {
    violation,
    ruleId: 'IS1001',
    source: 'rule-based',
    explanation: lang === 'ja'
      ? 'AuthorizationPolicyのALLOWルールに制限を追加してください。全トラフィックを許可するポリシーは危険です。'
      : 'Add source restrictions to this ALLOW AuthorizationPolicy. An ALLOW policy with no rules permits all traffic to the matched workload.',
    yamlPatch,
    autoApplicable: false,
    patchTarget: { file: violation.file, startLine: violation.line, endLine: violation.line + 5 },
  };
});

export function generateRuleFixes(
  violations: Violation[],
  graph: ResourceGraph,
  lang: FixLang,
): FixSuggestion[] {
  const suggestions: FixSuggestion[] = [];
  const seen = new Set<string>();

  for (const v of violations) {
    const key = `${v.rule}:${v.resource}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const fixFn = RULE_FIX_MAP.get(v.rule);
    if (!fixFn) continue;

    const suggestion = fixFn(v, graph, lang);
    if (suggestion) suggestions.push(suggestion);
  }

  return suggestions;
}
