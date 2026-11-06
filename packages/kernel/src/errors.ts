export class AuthenticationError extends Error {
  readonly status = 401;
  constructor(message = 'Authentication required') {
    super(message);
    this.name = 'AuthenticationError';
  }
}

export class AuthorizationError extends Error {
  readonly status = 403;
  constructor(readonly permission: string, readonly reason: string) {
    super(`Not allowed: ${permission} (${reason})`);
    this.name = 'AuthorizationError';
  }
}

/** Used for anything the caller may not know exists (cross-tenant, restricted): never 403. */
export class NotFoundError extends Error {
  readonly status = 404;
  constructor(message = 'Not found') {
    super(message);
    this.name = 'NotFoundError';
  }
}
