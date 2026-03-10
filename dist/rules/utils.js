"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.hasWildcard = hasWildcard;
exports.hasVerb = hasVerb;
exports.hasAnyVerb = hasAnyVerb;
exports.hasResource = hasResource;
exports.resourceLabel = resourceLabel;
exports.bindingLabel = bindingLabel;
exports.makeRoleKey = makeRoleKey;
exports.makeSAKey = makeSAKey;
exports.writeVerbs = writeVerbs;
exports.hasWriteVerb = hasWriteVerb;
exports.isClusterAdminEquivalent = isClusterAdminEquivalent;
function hasWildcard(arr) {
    return arr.includes('*');
}
function hasVerb(rule, verb) {
    return rule.verbs.includes('*') || rule.verbs.includes(verb);
}
function hasAnyVerb(rule, verbs) {
    return rule.verbs.includes('*') || verbs.some(v => rule.verbs.includes(v));
}
function hasResource(rule, resource) {
    return rule.resources.includes('*') || rule.resources.includes(resource);
}
function resourceLabel(r) {
    const ns = r.metadata.namespace ? `${r.metadata.namespace}/` : '';
    return `${r.kind}/${ns}${r.metadata.name}`;
}
function bindingLabel(b) {
    const ns = b.metadata.namespace ? `${b.metadata.namespace}/` : '';
    return `${b.kind}/${ns}${b.metadata.name}`;
}
function makeRoleKey(name, namespace) {
    return namespace ? `${namespace}/${name}` : name;
}
function makeSAKey(name, namespace) {
    return `${namespace}/${name}`;
}
function writeVerbs() {
    return ['create', 'update', 'patch', 'delete', 'deletecollection'];
}
function hasWriteVerb(rule) {
    return hasAnyVerb(rule, writeVerbs());
}
function isClusterAdminEquivalent(role) {
    for (const rule of role.rules) {
        if (rule.verbs.includes('*') && rule.resources.includes('*'))
            return true;
    }
    return false;
}
//# sourceMappingURL=utils.js.map