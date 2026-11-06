# ADR-0008: Tests against a real Postgres, one fresh database per test file

Status: accepted

Decision: integration tests create a fresh database per test file (bootstrap + migrations) on a Postgres server given by `DATABASE_ADMIN_URL`. CI uses a `postgres:17` service container. Tests connect as `ios_app`. Fixtures use the admin connection only for setup.

Deviation: Testcontainers (from the original proposal) is not used. CI service containers achieve the same isolation without needing a Docker socket in the test process. Local development needs a Postgres 16+.
