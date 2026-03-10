"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.RULE_MAP = exports.ALL_RULES = void 0;
const least_privilege_1 = require("./rb1/least-privilege");
const privilege_escalation_1 = require("./rb2/privilege-escalation");
const secret_access_1 = require("./rb3/secret-access");
const serviceaccount_1 = require("./rb4/serviceaccount");
const cluster_risks_1 = require("./rb5/cluster-risks");
const cross_namespace_1 = require("./rb6/cross-namespace");
exports.ALL_RULES = [
    ...least_privilege_1.RB1_RULES,
    ...privilege_escalation_1.RB2_RULES,
    ...secret_access_1.RB3_RULES,
    ...serviceaccount_1.RB4_RULES,
    ...cluster_risks_1.RB5_RULES,
    ...cross_namespace_1.RB6_RULES,
];
exports.RULE_MAP = new Map(exports.ALL_RULES.map(r => [r.id, r]));
//# sourceMappingURL=index.js.map