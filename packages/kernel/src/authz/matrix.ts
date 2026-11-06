import { PERMISSIONS } from './permissions';
import { SYSTEM_ROLE_KEYS, SYSTEM_ROLES } from './roles';

/** Markdown role × permission matrix. docs/security/role-matrix.md must contain it verbatim (tested). */
export function renderRoleMatrix(): string {
  const head = `| Permission | ${SYSTEM_ROLE_KEYS.join(' | ')} |\n|---|${SYSTEM_ROLE_KEYS.map(() => ':-:').join('|')}|`;
  const rows = PERMISSIONS.map(
    (p) => `| \`${p.key}\`${p.scopable ? ' (scopable)' : ''} | ${SYSTEM_ROLE_KEYS.map((r) => (SYSTEM_ROLES[r].permissions.has(p.key) ? '✔' : '')).join(' | ')} |`,
  );
  return [head, ...rows].join('\n');
}
