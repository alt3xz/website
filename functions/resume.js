const TURNSTILE_VERIFY_URL = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const RATE_LIMIT_WINDOW_MS = 60 * 60 * 1000;
const RATE_LIMIT_MAX = 5;

async function checkRateLimit(env, ip) {
  const key = `rl:${ip}`;
  const raw = await env.RESUME_KV.get(key);
  const now = Date.now();

  if (!raw) {
    await env.RESUME_KV.put(key, JSON.stringify({ count: 1, windowStart: now }), {
      expirationTtl: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
    return { allowed: true };
  }

  const record = JSON.parse(raw);

  if (now - record.windowStart > RATE_LIMIT_WINDOW_MS) {
    await env.RESUME_KV.put(key, JSON.stringify({ count: 1, windowStart: now }), {
      expirationTtl: Math.ceil(RATE_LIMIT_WINDOW_MS / 1000),
    });
    return { allowed: true };
  }

  if (record.count >= RATE_LIMIT_MAX) {
    const retryAfterMs = RATE_LIMIT_WINDOW_MS - (now - record.windowStart);
    return { allowed: false, retryAfterMs };
  }

  record.count += 1;
  await env.RESUME_KV.put(key, JSON.stringify(record), {
    expirationTtl: Math.ceil((RATE_LIMIT_WINDOW_MS - (now - record.windowStart)) / 1000),
  });
  return { allowed: true };
}

async function verifyPassword(password, storedHash) {
  const [salt, hash] = storedHash.split(':');
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 },
    keyMaterial, 256
  );
  const computed = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return computed === hash;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;
  const ip = request.headers.get('CF-Connecting-IP') ?? 'unknown';

  const rateCheck = await checkRateLimit(env, ip);
  if (!rateCheck.allowed) {
    const minutes = Math.ceil(rateCheck.retryAfterMs / 60000);
    return json({ error: `Too many attempts. Try again in ${minutes} minute${minutes !== 1 ? 's' : ''}.` }, 429);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid request.' }, 400);
  }

  const { username, password, turnstileToken } = body;

  if (!username || !password) {
    return json({ error: 'Username and password are required.' }, 400);
  }

  if (!turnstileToken) {
    return json({ error: 'Challenge token missing.' }, 400);
  }

  const verify = await fetch(TURNSTILE_VERIFY_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      secret: env.TURNSTILE_SECRET,
      response: turnstileToken,
      remoteip: ip,
    }),
  });

  const verifyData = await verify.json();
  if (!verifyData.success) {
    return json({ error: 'Challenge verification failed. Refresh and try again.' }, 403);
  }

  const row = await env.RESUME_DB.prepare(
    'SELECT password_hash FROM users WHERE username = ?'
  ).bind(username.toLowerCase().trim()).first();

  if (!row) {
    return json({ error: 'Invalid credentials.' }, 401);
  }

  const valid = await verifyPassword(password, row.password_hash);
  if (!valid) {
    return json({ error: 'Invalid credentials.' }, 401);
  }

  const pdf = await env.RESUME_BUCKET.get('resume.pdf');
  if (!pdf) {
    return json({ error: 'Resume not found.' }, 404);
  }

  return new Response(pdf.body, {
    headers: {
      'Content-Type': 'application/pdf',
      'Content-Disposition': 'attachment; filename="Alex-Bellina-Resume.pdf"',
      'Cache-Control': 'no-store',
    },
  });
}
