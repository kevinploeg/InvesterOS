import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { renderRoleMatrix } from '../src/authz/matrix';

const out = join(import.meta.dirname, '..', '..', '..', 'docs', 'security', 'role-matrix.md');
writeFileSync(out, `# System role × permission matrix

Generated from \`packages/kernel/src/authz/{permissions,roles}.ts\` by \`pnpm --filter @investoros/kernel gen:role-matrix\`.
A test fails if this file is out of date, so every change to role permissions shows up in review.

Notes:
- No role reaches **restricted** resources through this matrix alone. A live grant on the securable is required in addition
  (read-only permissions can alternatively be satisfied by \`restricted.oversight\`, which is audited).
- System roles are immutable through the application (enforced by RLS). Custom roles arrive in M1.

${renderRoleMatrix()}
`);
console.log(`wrote ${out}`);
