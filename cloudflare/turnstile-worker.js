/**
 * Turnstile-verified proxy between the patolicpa.com forms and Google Forms.
 *
 * Routes (all POST, multipart or urlencoded form bodies):
 *   /submit             contact form
 *   /submit/individual  new individual client intake
 *   /submit/business    new business client intake
 *
 * Secret binding required: TURNSTILE_SECRET
 */

const ALLOWED_ORIGINS = [
  'https://patolicpa.com',
  'https://www.patolicpa.com',
  'http://localhost:4321',
];

const TURNSTILE_VERIFY_URL =
  'https://challenges.cloudflare.com/turnstile/v0/siteverify';

const TEXT_MAX = 300;
const LONG_TEXT_MAX = 5000;

const text = (key, required = false, max = TEXT_MAX) => ({ key, required, type: 'text', max });
const longText = (key, required = false) => ({ key, required, type: 'text', max: LONG_TEXT_MAX });
const date = (key, required = false) => ({ key, required, type: 'date' });
const choice = (key, options, required = false) => ({ key, required, type: 'choice', options });

const FORMS = {
  '/submit': {
    url: 'https://docs.google.com/forms/d/e/1FAIpQLScfin0H4ZWmLHbp0PTLj9Hx8dJ31cAuz6gx_gmZkN5yGYabEQ/formResponse',
    fields: [
      text('entry.807866370', true), // name
      text('entry.837588410', true), // email
      text('entry.435000044'), // phone (optional)
      longText('entry.603333347', true), // message
    ],
  },
  '/submit/individual': {
    url: 'https://docs.google.com/forms/d/e/1FAIpQLSdH35AtSs_rbUDks822PbzfWLrOTFIXB6STAvbc4eC50iEj7Q/formResponse',
    fields: [
      choice('entry.34271753', ['Single', 'Married filing jointly', 'Married filing separately', 'Head of Household', 'Qualifying Surviving Spouse', 'Unsure'], true),
      choice('entry.899960226', ['Yes, I need to file in more than one state']),
      text('entry.1188523742', true), // taxpayer name
      date('entry.520230671', true), // taxpayer DOB
      text('entry.415572170', true), // taxpayer occupation
      text('entry.1428231473'), // spouse name
      date('entry.1177470525'), // spouse DOB
      text('entry.1119238828'), // spouse occupation
      text('entry.1081073742', true), // address
      text('entry.591580004', true), // city
      text('entry.1950372971'), // state
      text('entry.1985439352'), // zip
      text('entry.1304892919', true), // taxpayer phone
      text('entry.255512335', true), // taxpayer email
      text('entry.1163791718'), // spouse phone
      text('entry.540594178'), // spouse email
      choice('entry.1148722232', ['0', '1', '2', '3', '4+'], true),
      longText('entry.1172336037'), // notes
    ],
  },
  '/submit/business': {
    url: 'https://docs.google.com/forms/d/e/1FAIpQLSd0sYT47TX17l4myDK7MmsD5rcxSXGFNz38DQiKjo58VkjYcw/formResponse',
    fields: [
      choice('entry.1060108075', ['Corporation', 'S-Corp', 'Partnership', 'LLC', 'Sole Proprietorship', 'Unsure'], true),
      choice('entry.1545952302', ['General Partnership', 'Limited Partnership', 'Limited Liability Partnership', 'Limited Liability Company', 'Foreign Partnership', 'Other']),
      text('entry.564355504', true), // business name
      text('entry.240377413'), // DBA
      text('entry.1758505165', true), // primary contact
      text('entry.948455584', true), // address
      text('entry.444002907', true), // city
      text('entry.1846349346'), // state
      text('entry.521316135'), // zip
      text('entry.1291336900', true), // phone
      text('entry.792393476', true), // email
      date('entry.493536597'), // start date
      date('entry.2051969542'), // date incorporated
      text('entry.567888274'), // state incorporated
      date('entry.1209913412'), // S election date
      choice('entry.1847893626', ['Cash', 'Accrual', 'Other', 'Unsure']),
      text('entry.1827439795', true), // partners/shareholders
      longText('entry.1411316858'), // notes
    ],
  },
};

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

/**
 * Validate one submitted field against its spec and write it into the
 * Google Forms body. Returns false when the value is invalid.
 */
function applyField(spec, formData, body) {
  const value = field(formData, spec.key);

  if (!value) return !spec.required;

  if (spec.type === 'text') {
    if (value.length > spec.max) return false;
    body.set(spec.key, value);
    return true;
  }

  if (spec.type === 'choice') {
    if (!spec.options.includes(value)) return false;
    body.set(spec.key, value);
    return true;
  }

  if (spec.type === 'date') {
    // Native <input type="date"> submits YYYY-MM-DD; Google Forms wants the
    // parts as separate year/month/day fields.
    const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(value);
    if (!match) return false;
    body.set(`${spec.key}_year`, match[1]);
    body.set(`${spec.key}_month`, String(Number(match[2])));
    body.set(`${spec.key}_day`, String(Number(match[3])));
    return true;
  }

  return false;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      // Preflight. Headers are empty of Allow-Origin for disallowed origins,
      // which is enough for the browser to block the real request.
      return new Response(null, { status: 204, headers: corsHeaders(request) });
    }

    const form = FORMS[url.pathname];
    if (!form) {
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

    const forwardBody = new URLSearchParams();
    for (const spec of form.fields) {
      if (!applyField(spec, formData, forwardBody)) {
        return json(request, 400, { ok: false, error: 'invalid_input' });
      }
    }

    let upstream;
    try {
      upstream = await fetch(form.url, {
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
