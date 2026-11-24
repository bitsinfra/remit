// Keep the specification and SDK READMEs as their own source of truth.
export const externalPages = {
  'sdk/ts/README.md': 'sdks/typescript',
  'sdk/python/README.md': 'sdks/python',
  'sdk/go/README.md': 'sdks/go',
  'sdk/skill/SKILL.md': 'agents/authoring',
  'examples/README.md': 'examples',
  'backends/cloudflare/README.md': 'deployment/cloudflare',
  'SECURITY.md': 'security',
  'spec/README.md': 'specification',
  'spec/manifest.md': 'specification/manifest',
  'spec/rt.md': 'specification/types',
  'spec/sql.md': 'specification/sql',
  'spec/kernel.md': 'specification/kernel',
  'spec/admission.md': 'specification/admission',
  'spec/catalog.md': 'specification/catalog',
  'spec/receipts.md': 'specification/receipts',
  'spec/protocol.md': 'specification/transports',
  'spec/status.md': 'specification/status',
  'spec/diagnostics.md': 'specification/diagnostics',
  'spec/isolation.md': 'specification/isolation',
  'spec/threat-model.md': 'specification/threat-model',
  'spec/VERSIONING.md': 'specification/versioning',
  'spec/conformance/README.md': 'specification/conformance',
};

export function pageId(source) {
  return externalPages[source] ?? source.replace(/^docs\//, '').replace(/\.mdx?$/, '');
}

export const sidebar = [
  { label: 'Getting started', items: [
    { slug: 'index', label: 'Introduction' }, 'installation',
    { slug: 'quickstart-typescript', label: 'First exchange · TypeScript' },
    { slug: 'quickstart-python', label: 'First exchange · Python' }, 'concepts', 'examples',
  ] },
  { label: 'Build with Remit', items: [
    'agent-to-agent', 'queries', 'kernels', 'result-types', 'receipts', 'integrations',
    { slug: 'agents/authoring', label: 'Authoring guide for agents' },
  ] },
  { label: 'Run a holder', items: [
    'holders', 'policies', 'operations',
    { slug: 'deployment/cloudflare', label: 'Cloudflare Workers' },
  ] },
  { label: 'SDKs and tools', items: [
    { slug: 'sdks/typescript', label: 'TypeScript' },
    { slug: 'sdks/python', label: 'Python' },
    { slug: 'sdks/go', label: 'Go' }, 'cli', 'troubleshooting',
  ] },
  { label: 'Protocol specification', collapsed: true, items: [
    { slug: 'specification', label: 'Overview' },
    { slug: 'specification/manifest', label: 'Manifest and envelope' },
    { slug: 'specification/types', label: 'Remit Types' },
    { slug: 'specification/sql', label: 'SQL dialect' },
    { slug: 'specification/kernel', label: 'Kernel contract' },
    { slug: 'specification/catalog', label: 'Catalog' },
    { slug: 'specification/admission', label: 'Admission' },
    { slug: 'specification/transports', label: 'HTTP, MCP and A2A' },
    { slug: 'specification/receipts', label: 'Receipts and replay' },
    { slug: 'specification/status', label: 'Status and accounting' },
    { slug: 'specification/diagnostics', label: 'Diagnostic codes' },
    { slug: 'specification/isolation', label: 'Isolation' },
    { slug: 'specification/threat-model', label: 'Threat model' },
    { slug: 'specification/versioning', label: 'Versioning' },
    { slug: 'specification/conformance', label: 'Conformance' },
    { slug: 'security', label: 'Security and reporting' },
  ] },
];
