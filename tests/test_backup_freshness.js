const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const source = fs.readFileSync('static/admin.js', 'utf8');
const start = source.indexOf('function backupFreshness(');
const end = source.indexOf('function renderBackupNode(', start);
const context = vm.createContext({});
vm.runInContext(source.slice(start, end), context);
const now = Date.parse('2026-09-19T20:00:00Z');
function record(hours, status = 'success') { return {source_node:'pi', status, checksum_status:'verified', verification_status:'verified', finished_at:new Date(now-hours*3600000).toISOString()}; }
for (const [hours, expected] of [[23.99,'OK'],[24,'warning'],[36,'warning'],[36.01,'critical'],[-1,'unknown']]) {
  assert.equal(context.backupFreshness([record(hours)], 'pi', now).level, expected);
}
assert.equal(context.backupFreshness([record(1,'failed'),record(37)],'pi',now).level,'critical');
assert.equal(context.backupFreshness([record(1)],'cloud',now).level,'unknown');
assert.equal(context.backupFreshness([],'pi',now).level,'unknown');
console.log('PASS: freshness thresholds, failed latest attempt, missing source, future timestamp');
