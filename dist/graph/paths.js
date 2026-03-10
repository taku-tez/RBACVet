"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.extractPaths = extractPaths;
function parseNodeId(id, nodes) {
    const node = nodes.get(id);
    if (!node)
        return null;
    return { kind: node.kind, name: node.name, namespace: node.namespace };
}
function extractPaths(graph, scores) {
    const scoreMap = new Map();
    if (scores) {
        for (const s of scores)
            scoreMap.set(s.name, s);
    }
    const paths = [];
    for (const rawPath of graph.escalationPaths) {
        if (rawPath.length < 2)
            continue;
        const saNodeId = rawPath[0];
        const saNode = graph.nodes.get(saNodeId);
        if (!saNode || saNode.kind !== 'ServiceAccount')
            continue;
        const lastNode = graph.nodes.get(rawPath[rawPath.length - 1]);
        const endsAtClusterAdmin = lastNode?.isClusterAdminEquivalent ?? false;
        const pathNodes = rawPath
            .map(id => parseNodeId(id, graph.nodes))
            .filter((n) => n !== null);
        const saScoreKey = `ServiceAccount/${saNode.namespace ?? 'default'}/${saNode.name}`;
        const saScore = scoreMap.get(saScoreKey);
        paths.push({
            serviceAccount: {
                name: saNode.name,
                namespace: saNode.namespace ?? 'default',
            },
            path: pathNodes,
            endsAtClusterAdmin,
            score: saScore?.score,
            riskLevel: saScore?.level,
        });
    }
    // Sort by score descending
    paths.sort((a, b) => (b.score ?? 0) - (a.score ?? 0));
    return paths;
}
//# sourceMappingURL=paths.js.map