"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseFile = parseFile;
exports.parseFiles = parseFiles;
const yaml = __importStar(require("js-yaml"));
function getLineNumber(content, offset) {
    return content.slice(0, offset).split('\n').length;
}
function buildPolicyRules(raw) {
    if (!Array.isArray(raw))
        return [];
    return raw.map((r) => {
        const rule = r;
        return {
            apiGroups: Array.isArray(rule.apiGroups) ? rule.apiGroups : [],
            resources: Array.isArray(rule.resources) ? rule.resources : [],
            verbs: Array.isArray(rule.verbs) ? rule.verbs : [],
            resourceNames: Array.isArray(rule.resourceNames) ? rule.resourceNames : undefined,
        };
    });
}
function buildSubjects(raw) {
    if (!Array.isArray(raw))
        return [];
    return raw.map((s) => {
        const subj = s;
        return {
            kind: subj.kind || 'ServiceAccount',
            name: subj.name || '',
            namespace: subj.namespace,
        };
    });
}
function buildRoleRef(raw) {
    const ref = raw || {};
    return {
        kind: ref.kind || 'Role',
        name: ref.name || '',
        apiGroup: ref.apiGroup || 'rbac.authorization.k8s.io',
    };
}
function buildMeta(raw) {
    const m = raw || {};
    return {
        name: m.name || '',
        namespace: m.namespace,
        annotations: m.annotations,
        labels: m.labels,
    };
}
function parseFile(content, filePath) {
    const resources = [];
    const errors = [];
    // Split on --- to track approximate line numbers per document
    const docSeparatorRegex = /^---[ \t]*$/m;
    const docStarts = [0];
    let match;
    const sepRegex = /^---[ \t]*$/gm;
    while ((match = sepRegex.exec(content)) !== null) {
        docStarts.push(match.index + match[0].length + 1);
    }
    let docIndex = 0;
    try {
        yaml.loadAll(content, (doc) => {
            if (doc === null || doc === undefined) {
                docIndex++;
                return;
            }
            const startOffset = docStarts[docIndex] ?? 0;
            const sourceLine = getLineNumber(content, startOffset);
            docIndex++;
            const raw = doc;
            const kind = raw.kind;
            const apiVersion = raw.apiVersion || '';
            const metadata = buildMeta(raw.metadata);
            if (!metadata.name)
                return;
            try {
                switch (kind) {
                    case 'Role':
                    case 'ClusterRole': {
                        const role = {
                            kind: kind,
                            apiVersion,
                            metadata,
                            rules: buildPolicyRules(raw.rules),
                            sourceFile: filePath,
                            sourceLine,
                        };
                        resources.push(role);
                        break;
                    }
                    case 'RoleBinding':
                    case 'ClusterRoleBinding': {
                        const binding = {
                            kind: kind,
                            apiVersion,
                            metadata,
                            subjects: buildSubjects(raw.subjects),
                            roleRef: buildRoleRef(raw.roleRef),
                            sourceFile: filePath,
                            sourceLine,
                        };
                        resources.push(binding);
                        break;
                    }
                    case 'ServiceAccount': {
                        const sa = {
                            kind: 'ServiceAccount',
                            apiVersion,
                            metadata,
                            automountServiceAccountToken: raw.automountServiceAccountToken,
                            sourceFile: filePath,
                            sourceLine,
                        };
                        resources.push(sa);
                        break;
                    }
                    // Unknown kinds are silently skipped
                }
            }
            catch (e) {
                errors.push({
                    file: filePath,
                    line: sourceLine,
                    message: e.message,
                });
            }
        });
    }
    catch (e) {
        const yamlErr = e;
        errors.push({
            file: filePath,
            line: yamlErr.mark?.line ?? 0,
            message: yamlErr.message,
        });
    }
    return { resources, errors };
}
function parseFiles(files) {
    const allResources = [];
    const allErrors = [];
    for (const f of files) {
        const result = parseFile(f.content, f.path);
        allResources.push(...result.resources);
        allErrors.push(...result.errors);
    }
    return { resources: allResources, errors: allErrors };
}
//# sourceMappingURL=parser.js.map