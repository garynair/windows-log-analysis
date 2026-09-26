// Runs the Code-node JavaScript straight from the n8n workflow export with
// n8n's globals stubbed, against the same cases as tests/test_digest.py.
// Run: node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = p => readFileSync(new URL(`../${p}`, import.meta.url), 'utf8');
const workflow = JSON.parse(read('n8n/windows_log_digest_workflow.json'));
const scenarios = JSON.parse(read('tests/scenarios.json'));
const node = name => workflow.nodes.find(n => n.name === name);

function runCode(name, upstream, input = {}) {
  const $ = n => {
    if (!(n in upstream)) throw new Error(`unexpected $('${n}')`);
    return { first: () => ({ json: upstream[n] }) };
  };
  const $input = { first: () => ({ json: input }) };
  const $now = { toISODate: () => '2026-09-25' };
  return new Function('$', '$input', '$now', node(name).parameters.jsCode)($, $input, $now)[0].json;
}

const lokiVector = rows => ({ data: { result: rows.map(([event_id, channel, n]) => ({ metric: { event_id, channel }, value: [0, String(n)] })) } });
const lokiDays = days => ({ data: { result: [{ values: Array.from({ length: 8 }, (_, i) => [i, i < 8 - days ? '0' : '12']) }] } });

function buildFacts(c) {
  return runCode('Build Facts', {
    'Counts 24h': lokiVector(c.c24),
    'Counts 7d': lokiVector(c.c7),
    'History Days': lokiDays(c.history_days),
    'Notable Events': { data: { result: [] } },
  });
}

for (const c of scenarios.facts) {
  test(`facts: ${c.name}`, () => {
    const out = buildFacts(c);
    assert.equal(out.severity_floor, c.expected.floor);
    assert.deepEqual(out.severity_reasons, c.expected.reasons);
    assert.deepEqual(out.rule_checks, c.expected.checks);
    assert.deepEqual(out.facts.event_counts.filter(r => r.spike).map(r => r.event_id), c.expected.spikes);
    assert.equal(out.facts.baseline_days, c.expected.baseline_days);
    assert.deepEqual(out.facts.severity_reasons, c.expected.reasons, 'the model sees the rule reasons');
  });
}

for (const c of scenarios.finalize) {
  test(`finalize: ${c.name}`, () => {
    const bf = { severity_floor: c.floor, severity_reasons: c.reasons, rule_checks: c.rule_checks, facts: { event_counts: [] } };
    const { digest, lokiBody } = runCode('Finalize & Apply Floor', { 'Build Facts': bf }, { text: c.llm });
    assert.equal(digest.severity, c.expected.severity);
    assert.equal(digest.headline, c.expected.headline);
    assert.deepEqual(digest.recommended_checks, c.expected.checks);
    assert.ok(Array.isArray(digest.findings));
    assert.deepEqual(lokiBody.streams[0].stream, { job: 'ai_digest', source: 'n8n', severity: c.expected.severity });
  });
}

test('workflow: every connection points at an existing node', () => {
  const names = new Set(workflow.nodes.map(n => n.name));
  for (const [from, outs] of Object.entries(workflow.connections)) {
    assert.ok(names.has(from), from);
    for (const c of Object.values(outs).flat(2)) assert.ok(names.has(c.node), `${from} -> ${c.node}`);
  }
});

test('workflow: Loki is reached over the stack network, not a host port', () => {
  for (const n of workflow.nodes.filter(n => n.type.endsWith('httpRequest'))) {
    assert.match(n.parameters.url, /^http:\/\/loki:3100\//, n.name);
  }
});

test('workflow: the prompt tells the model to explain rule reasons', () => {
  assert.match(node('Summarize').parameters.text, /facts\.severity_reasons/);
});

test('workflow and script flag the same event IDs', () => {
  const script = read('digest/windows_digest.py');
  const pyIds = name => new Set(script.match(new RegExp(`^${name} = set\\(\\[(.*?)\\]\\)`, 'm'))[1].match(/\d+/g));
  const js = node('Build Facts').parameters.jsCode;
  const jsIds = name => new Set(js.match(new RegExp(`const ${name} = \\[(.*?)\\]`))[1].match(/\d+/g));
  for (const name of ['CRITICAL', 'WATCH']) assert.deepEqual(jsIds(name), pyIds(name), name);
});

test('no credentials are committed in the workflow', () => {
  for (const n of workflow.nodes) {
    for (const cred of Object.values(n.credentials || {})) assert.ok(!cred.id || cred.id === '', `${n.name} has a credential id`);
  }
});
