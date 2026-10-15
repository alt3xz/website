async function hashPassword(password) {
  const salt = crypto.randomUUID().replace(/-/g, '');
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']
  );
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: enc.encode(salt), iterations: 100000 },
    keyMaterial, 256
  );
  const hash = btoa(String.fromCharCode(...new Uint8Array(bits)));
  return `${salt}:${hash}`;
}

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

export async function onRequestPost(context) {
  const { request, env } = context;

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: 'Invalid request.' }, 400);
  }

  const { username, password, setupToken } = body;

  if (!env.SETUP_TOKEN || setupToken !== env.SETUP_TOKEN) {
    return json({ error: 'Unauthorized.' }, 401);
  }

  if (!username || !password) {
    return json({ error: 'Username and password are required.' }, 400);
  }

  if (password.length < 8) {
    return json({ error: 'Password must be at least 8 characters.' }, 400);
  }

  const passwordHash = await hashPassword(password);

  try {
    await env.RESUME_DB.prepare(
      'INSERT INTO users (username, password_hash) VALUES (?, ?)'
    ).bind(username.toLowerCase().trim(), passwordHash).run();
  } catch (e) {
    if (e.message?.includes('UNIQUE')) {
      return json({ error: 'Username already exists.' }, 409);
    }
    return json({ error: 'Failed to create user.' }, 500);
  }

  return json({ ok: true, username: username.toLowerCase().trim() }, 201);
}
