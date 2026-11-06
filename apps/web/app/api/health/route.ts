import { NextResponse } from 'next/server';
import { ensureSynthetic } from '@/server/runtime';

export const dynamic = 'force-dynamic';

export async function GET(): Promise<NextResponse> {
  try {
    await ensureSynthetic();
    return NextResponse.json({ status: 'ok', data: 'synthetic' });
  } catch {
    return NextResponse.json({ status: 'unavailable' }, { status: 503 });
  }
}
