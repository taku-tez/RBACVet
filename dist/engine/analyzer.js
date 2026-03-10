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
exports.analyzeResources = analyzeResources;
exports.analyzeFiles = analyzeFiles;
exports.collectYamlFiles = collectYamlFiles;
const fs = __importStar(require("fs"));
const path = __importStar(require("path"));
const parser_1 = require("../parser/parser");
const index_1 = require("../rules/index");
const scorer_1 = require("./scorer");
const utils_1 = require("../rules/utils");
function buildGraph(resources) {
    const roles = new Map();
    const clusterRoles = new Map();
    const roleBindings = [];
    const clusterRoleBindings = [];
    const serviceAccounts = new Map();
    for (const r of resources) {
        switch (r.kind) {
            case 'Role':
                roles.set((0, utils_1.makeRoleKey)(r.metadata.name, r.metadata.namespace), r);
                break;
            case 'ClusterRole':
                clusterRoles.set(r.metadata.name, r);
                break;
            case 'RoleBinding':
                roleBindings.push(r);
                break;
            case 'ClusterRoleBinding':
                clusterRoleBindings.push(r);
                break;
            case 'ServiceAccount': {
                const ns = r.metadata.namespace || 'default';
                serviceAccounts.set((0, utils_1.makeSAKey)(r.metadata.name, ns), r);
                break;
            }
        }
    }
    return { roles, clusterRoles, roleBindings, clusterRoleBindings, serviceAccounts };
}
function analyzeResources(resources, config) {
    const graph = buildGraph(resources);
    const ctx = { graph, config };
    const rawViolations = [];
    for (const rule of index_1.ALL_RULES) {
        if (config.ignore.includes(rule.id))
            continue;
        rawViolations.push(...rule.check(ctx));
    }
    // Apply severity overrides
    const violations = rawViolations.map(v => {
        const override = config.override[v.rule];
        return override ? { ...v, severity: override.severity } : v;
    });
    violations.sort((a, b) => {
        if (a.file !== b.file)
            return a.file.localeCompare(b.file);
        return a.line - b.line;
    });
    const scoring = (0, scorer_1.computeScores)(graph, violations, config.riskScoreThreshold, config.trustedClusterAdminBindings);
    return { violations, scores: scoring.scores, graph };
}
function analyzeFiles(files, config) {
    const allResources = [];
    const allErrors = [];
    for (const file of files) {
        const content = fs.readFileSync(file, 'utf-8');
        const result = (0, parser_1.parseFile)(content, file);
        allResources.push(...result.resources);
        allErrors.push(...result.errors);
    }
    const { violations, scores, graph } = analyzeResources(allResources, config);
    return { violations, scores, graph, parseErrors: allErrors };
}
function collectYamlFiles(dir) {
    const results = [];
    const entries = fs.readdirSync(dir, { recursive: true, encoding: 'utf-8' });
    for (const entry of entries) {
        if (entry.endsWith('.yaml') || entry.endsWith('.yml')) {
            results.push(path.join(dir, entry));
        }
    }
    return results;
}
//# sourceMappingURL=analyzer.js.map