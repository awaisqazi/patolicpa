/**
 * Turnstile-verified proxy between the patolicpa.com contact form and Google Forms.
 *
 * Route: POST /submit
 * Secret binding required: TURNSTILE_SECRET
 */

const ALLOWED_ORIGINS = [
  'https://patolicpa.com',
  'https://www.patolicpa.com',
  'http://localhost:4321',
];

const GOOGLE_FORM_URL =
  'https://docs.google.com/forms/d/e/1FAIpQLScfin0H4ZWmLHbp0PTLj9Hx8dJ31cAuz6gx_gmZkN5yGYabEQ/formResponse';

const TURNSTILE_VERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const ENTRY_FIELDS = [
  'entry.807866370', // name
  'entry.837588410', // email
  'entry.435000044', // phone (optional)
  'entry.603333347', // message
];

const MAX_MESSAGE_LENGTH = 5000;

function corsHeaders(request) {
  const origin = request.headers.get('Origin');
  const headers = {
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Access-Control-Max-Age': '86400',
    Vary: 'Origin',
  };

  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
  }

  return headers;
}

function json(request, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...corsHeaders(request),
    },
  });
}

function field(formData, name) {
  const value = formData.get(name);
  return typeof value === 'string' ? value.trim() : '';
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      // Preflight. Headers are empty of Allow-Origin for disallowed origins,
      // which is enough for the browser to block the real request.
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    if (url.pathname !== '/submit') {
      return json(request, 404, { ok: false, error: 'not_found' });
    }

    if (request.method !== 'POST') {
      return json(request, 405, { ok: false, error: 'method_not_allowed' });
    }

    // Hard origin rejection: refuse before any work happens. Browser bots
    // carry a real Origin; non-browser bots must at least spoof an allowed one.
    const origin = request.headers.get('Origin');
    if (!origin || !ALLOWED_ORIGINS.includes(origin)) {
      return json(request, 403, { ok: false, error: 'forbidden_origin' });
    }

    let formData;
    try {
      formData = await request.formData();
    } catch {
      return json(request, 400, { ok: false, error: 'invalid_request' });
    }

    const token = field(formData, 'cf-turnstile-response');
    if (!token) {
      return json(request, 403, { ok: false, error: 'verification_failed' });
    }

    const verifyBody = new URLSearchParams({
      secret: env.TURNSTILE_SECRET,
      response: token,
    });

    const remoteIp = request.headers.get('CF-Connecting-IP');
    if (remoteIp) verifyBody.set('remoteip', remoteIp);

    let verification;
    try {
      const verifyRes = await fetch(TURNSTILE_VERIFY_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: verifyBody,
      });
      verification = await verifyRes.json();
    } catch {
      return json(request, 403, { ok: false, error: 'verification_failed' });
    }

    if (!verification || verification.success !== true) {
      return json(request, 403, { ok: false, error: 'verification_failed' });
    }

    const name = field(formData, 'entry.807866370');
    const email = field(formData, 'entry.837588410');
    const phone = field(formData, 'entry.435000044');
    const message = field(formData, 'entry.603333347');

    if (!name || !email || !message || message.length > MAX_MESSAGE_LENGTH) {
      return json(request, 400, { ok: false, error: 'invalid_input' });
    }

    const values = [name, email, phone, message];
    const forwardBody = new URLSearchParams();
    ENTRY_FIELDS.forEach((key, index) => {
      forwardBody.set(key, values[index]);
    });

    let upstream;
    try {
      upstream = await fetch(GOOGLE_FORM_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: forwardBody,
        // Google answers with a redirect on some form configurations; treat it
        // as a completed submission rather than following it.
        redirect: 'manual',
      });
    } catch {
      return json(request, 502, { ok: false, error: 'upstream_error' });
    }

    if (upstream.status < 200 || upstream.status >= 400) {
      return json(request, 502, { ok: false, error: 'upstream_error' });
    }

    return json(request, 200, { ok: true });
  },
};
