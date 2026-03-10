#!/usr/bin/env node
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
const fs = __importStar(require("fs"));
const analyzer_1 = require("./engine/analyzer");
const config_1 = require("./engine/config");
const tty_1 = require("./formatter/tty");
const json_1 = require("./formatter/json");
const sarif_1 = require("./formatter/sarif");
const diff_1 = require("./formatter/diff");
const graph_1 = require("./formatter/graph");
const builder_1 = require("./graph/builder");
const paths_1 = require("./graph/paths");
const dot_1 = require("./graph/dot");
const VERSION = '0.3.0';
function printUsage() {
    console.log(`
rbacvet - Kubernetes RBAC security analyzer

Usage:
  rbacvet [options] [files...]

Options:
  --dir <path>              Scan all YAML files in directory recursively
  --cluster                 Analyze live cluster (uses current kubeconfig)
  --context <name>          Kubeconfig context to use (with --cluster)
  --namespace <ns>          Namespace to scan (with --cluster)
  --all-namespaces          Scan all namespaces (with --cluster)
  --diff                    Compare cluster vs local manifests
  --map                     Output privilege escalation graph
  --map-format <dot|json>   Graph output format (default: dot)
  --format <tty|json|sarif> Output format (default: tty)
  --ignore <rule>           Ignore rule ID (repeatable)
  --severity <level>        Minimum severity: error, warning, info (default: info)
  --config <path>           Config file path
  --no-color                Disable colored output
  -h, --help                Show this help
  -v, --version             Show version

Examples:
  rbacvet role.yaml rolebinding.yaml
  rbacvet --dir ./rbac/
  rbacvet --cluster --all-namespaces
  rbacvet --cluster --diff --dir ./rbac/
  rbacvet --map --dir ./rbac/ > escalation.dot
  rbacvet --map --map-format json --cluster | jq '.escalationPaths'
  rbacvet --format sarif --dir ./rbac/ > results.sarif
`);
}
function parseArgs(args) {
    const opts = {
        cluster: false,
        allNamespaces: false,
        diff: false,
        map: false,
        mapFormat: 'dot',
        format: 'tty',
        ignore: [],
        severity: 'info',
        noColor: false,
        files: [],
    };
    for (let i = 0; i < args.length; i++) {
        switch (args[i]) {
            case '--dir':
                opts.dir = args[++i];
                break;
            case '--cluster':
                opts.cluster = true;
                break;
            case '--context':
                opts.context = args[++i];
                break;
            case '--namespace':
                opts.namespace = args[++i];
                break;
            case '--all-namespaces':
                opts.allNamespaces = true;
                break;
            case '--diff':
                opts.diff = true;
                break;
            case '--map':
                opts.map = true;
                break;
            case '--map-format':
                opts.mapFormat = args[++i] || 'dot';
                break;
            case '--format':
                opts.format = args[++i] || 'tty';
                break;
            case '--ignore':
                opts.ignore.push(args[++i]);
                break;
            case '--severity':
                opts.severity = args[++i] || 'info';
                break;
            case '--config':
                opts.configPath = args[++i];
                break;
            case '--no-color':
                opts.noColor = true;
                break;
            default:
                if (!args[i].startsWith('-'))
                    opts.files.push(args[i]);
                break;
        }
    }
    return opts;
}
function filterBySeverity(violations, minSeverity) {
    const order = { error: 2, warning: 1, info: 0 };
    const min = order[minSeverity] ?? 0;
    return violations.filter(v => (order[v.severity] ?? 0) >= min);
}
async function main() {
    const args = process.argv.slice(2);
    if (args.length === 0 || args.includes('-h') || args.includes('--help')) {
        printUsage();
        process.exit(0);
    }
    if (args.includes('-v') || args.includes('--version')) {
        console.log(`rbacvet ${VERSION}`);
        process.exit(0);
    }
    const opts = parseArgs(args);
    const config = (0, config_1.loadConfig)(opts.configPath);
    config.ignore = [...config.ignore, ...opts.ignore];
    const useColor = !opts.noColor && process.stdout.isTTY !== false;
    // --- --diff mode ---
    if (opts.diff) {
        if (!opts.cluster) {
            console.error('Error: --diff requires --cluster');
            process.exit(2);
        }
        if (opts.files.length === 0 && !opts.dir) {
            console.error('Error: --diff requires local files or --dir to compare against');
            process.exit(2);
        }
        const { fetchClusterResources } = await Promise.resolve().then(() => __importStar(require('./cluster/fetcher')));
        const { diffResources } = await Promise.resolve().then(() => __importStar(require('./cluster/diff')));
        const localFiles = opts.dir ? (0, analyzer_1.collectYamlFiles)(opts.dir) : opts.files;
        const localResult = (0, analyzer_1.analyzeFiles)(localFiles, config);
        const clusterResources = await fetchClusterResources({
            context: opts.context,
            namespace: opts.namespace,
            allNamespaces: opts.allNamespaces,
        });
        const clusterResourceList = [...clusterResources];
        const localResourceList = [
            ...localResult.graph.roles.values(),
            ...localResult.graph.clusterRoles.values(),
            ...localResult.graph.roleBindings,
            ...localResult.graph.clusterRoleBindings,
            ...localResult.graph.serviceAccounts.values(),
        ];
        const entries = diffResources(clusterResourceList, localResourceList);
        console.log((0, diff_1.formatDiff)(entries, useColor));
        process.exit(entries.length > 0 ? 1 : 0);
    }
    // --- Collect resources ---
    let resources;
    let filesCount = 0;
    if (opts.cluster) {
        const { fetchClusterResources } = await Promise.resolve().then(() => __importStar(require('./cluster/fetcher')));
        const clusterResources = await fetchClusterResources({
            context: opts.context,
            namespace: opts.namespace,
            allNamespaces: opts.allNamespaces,
        });
        const result = (0, analyzer_1.analyzeResources)(clusterResources, config);
        resources = result;
    }
    else {
        let files = [];
        if (opts.dir) {
            if (!fs.existsSync(opts.dir)) {
                console.error(`Error: Directory not found: ${opts.dir}`);
                process.exit(2);
            }
            files = (0, analyzer_1.collectYamlFiles)(opts.dir);
        }
        else if (opts.files.length > 0) {
            files = opts.files;
            for (const f of files) {
                if (!fs.existsSync(f)) {
                    console.error(`Error: File not found: ${f}`);
                    process.exit(2);
                }
            }
        }
        else {
            console.error('Error: No files specified. Use --dir, --cluster, or provide file paths.');
            process.exit(2);
        }
        if (files.length === 0) {
            console.log('No YAML files found');
            process.exit(0);
        }
        const result = (0, analyzer_1.analyzeFiles)(files, config);
        resources = result;
        filesCount = files.length;
        for (const err of result.parseErrors) {
            console.error(`Parse error in ${err.file}:${err.line}: ${err.message}`);
        }
    }
    // --- --map mode ---
    if (opts.map) {
        const escalationGraph = (0, builder_1.buildEscalationGraph)(resources.graph);
        const paths = (0, paths_1.extractPaths)(escalationGraph, resources.scores);
        if (opts.mapFormat === 'json') {
            console.log(JSON.stringify({ escalationPaths: paths, cycles: escalationGraph.cycles }, null, 2));
        }
        else {
            // DOT format to stdout; summary to stderr
            process.stderr.write((0, graph_1.formatGraphSummary)(escalationGraph, paths, useColor) + '\n');
            console.log((0, dot_1.toDOT)(escalationGraph));
        }
        process.exit(0);
    }
    // --- Normal analysis output ---
    const violations = filterBySeverity(resources.violations, opts.severity);
    switch (opts.format) {
        case 'json': {
            const allResources = [
                ...resources.graph.roles.values(),
                ...resources.graph.clusterRoles.values(),
                ...resources.graph.roleBindings,
                ...resources.graph.clusterRoleBindings,
                ...resources.graph.serviceAccounts.values(),
            ];
            console.log((0, json_1.formatJSON)(violations, resources.scores, filesCount, allResources));
            break;
        }
        case 'sarif':
            console.log((0, sarif_1.formatSARIF)(violations));
            break;
        default:
            console.log((0, tty_1.formatTTY)(violations, resources.scores, useColor));
            break;
    }
    const hasErrors = violations.some(v => v.severity === 'error');
    const hasWarnings = violations.some(v => v.severity === 'warning');
    const thresholdExceeded = resources.scores.some(s => s.score >= config.riskScoreThreshold);
    if (hasErrors || thresholdExceeded)
        process.exit(2);
    else if (hasWarnings)
        process.exit(1);
    else
        process.exit(0);
}
main().catch(err => {
    console.error(`Error: ${err.message}`);
    process.exit(2);
});
//# sourceMappingURL=index.js.map