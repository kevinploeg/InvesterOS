export async function register(): Promise<void> {
  if (process.env.NEXT_RUNTIME === 'nodejs') {
    const { ensureSynthetic } = await import('./src/server/runtime');
    // Fail fast at boot: no synthetic marker => the server refuses to start serving.
    await ensureSynthetic();
  }
}
