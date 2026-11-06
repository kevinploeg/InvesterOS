import { v7 } from 'uuid';

/** UUIDv7: time-ordered (index friendly), non-enumerable. Generated in the app layer. */
export const newId = (): string => v7();

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
export const isUuid = (s: unknown): s is string => typeof s === 'string' && UUID_RE.test(s);
