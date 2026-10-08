// Server-side gate: every request (including data.bin) needs HTTP Basic auth before any file is served.
// Only a SHA-256 of "user:password" lives here, never the password itself.
import { next } from '@vercel/functions';

const EXPECTED = '25d771e34f732dc7a65d8c88988225e008895a05825d7a01364e130275b55f8b';

async function sha256(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, '0')).join('');
}

export const config = { matcher: '/:path*' };

export default async function middleware(request) {
  const header = request.headers.get('authorization') || '';
  if (header.startsWith('Basic ')) {
    try {
      if ((await sha256(atob(header.slice(6)))) === EXPECTED) return next();
    } catch {}
  }
  return new Response('Authentication required', {
    status: 401,
    headers: {
      'WWW-Authenticate': 'Basic realm="Watad dashboard", charset="UTF-8"',
      'Cache-Control': 'no-store',
    },
  });
}
