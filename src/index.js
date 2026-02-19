const DEFAULT_SERVICES = [
  {
    slug: "managed-it-services",
    title: "Managed IT Services",
    summary: "24/7 monitoring, endpoint management, and support operations.",
  },
  {
    slug: "cybersecurity",
    title: "Cybersecurity",
    summary: "Identity controls, endpoint hardening, and practical security operations.",
  },
  {
    slug: "cloud-solutions",
    title: "Cloud Solutions",
    summary: "Cloud planning, migration, and operational support.",
  },
  {
    slug: "computer-repair",
    title: "Computer Repair",
    summary: "Hardware diagnostics, component replacement, and stabilization.",
  },
];

const DEFAULT_POSTS = [
  {
    slug: "the-future-of-cloud-computing-in-2025",
    title: "The Future of Cloud Computing in 2025",
    excerpt: "Cloud trends and practical decisions for growing teams.",
    published_at: "2026-02-01T12:00:00.000Z",
  },
  {
    slug: "essential-cybersecurity-practices-for-small-businesses",
    title: "Essential Cybersecurity Practices for Small Businesses",
    excerpt: "Security baseline controls that reduce incident risk.",
    published_at: "2026-01-20T12:00:00.000Z",
  },
];

const EPHEMERAL_STATE = {
  contacts: [],
  quotes: [],
};

const RELEASE_ID = "2026-02-19-fix2";

const STATIC_ALIASES = {
  "/request_quote": "/request-quote",
  "/remote_support": "/remote-support",
};

function json(payload, status = 200) {
  const response = new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
  response.headers.set("x-release", RELEASE_ID);
  return response;
}

function redirect(location, status = 303) {
  const response = new Response(null, {
    status,
    headers: { location },
  });
  response.headers.set("x-release", RELEASE_ID);
  return response;
}

function formErrorPage(title, detail, status = 400) {
  const safeTitle = String(title || "Form Error");
  const safeDetail = String(detail || "Invalid request");
  const response = new Response(
    `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>${safeTitle}</title></head>
<body style="font-family:Arial,sans-serif;padding:20px;background:#f8fafc;color:#111827;">
  <h1>${safeTitle}</h1>
  <p>${safeDetail}</p>
  <p><a href="/">Return Home</a></p>
</body></html>`,
    {
      status,
      headers: { "content-type": "text/html; charset=utf-8" },
    }
  );
  response.headers.set("x-release", RELEASE_ID);
  response.headers.set("cache-control", "no-store, no-cache, must-revalidate");
  return response;
}

function normalizeText(value, max = 2000) {
  return String(value ?? "").trim().slice(0, max);
}

function firstNonEmpty(...values) {
  for (const value of values) {
    if (Array.isArray(value)) {
      const joined = value.map((v) => normalizeText(v, 500)).filter(Boolean).join(", ");
      if (joined) return joined;
      continue;
    }
    const next = normalizeText(value, 5000);
    if (next) return next;
  }
  return "";
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value ?? "").trim());
}

function createTicketNumber() {
  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  const token = crypto.randomUUID().split("-")[0].toUpperCase();
  return `RS-${stamp}-${token}`;
}

async function parseBody(request) {
  const contentType = request.headers.get("content-type") || "";

  if (contentType.includes("application/json")) {
    return (await request.json().catch(() => ({}))) || {};
  }

  if (
    contentType.includes("application/x-www-form-urlencoded") ||
    contentType.includes("multipart/form-data")
  ) {
    const formData = await request.formData();
    const body = {};
    for (const [key, value] of formData.entries()) {
      const val = typeof value === "string" ? value : String(value ?? "");
      if (Object.prototype.hasOwnProperty.call(body, key)) {
        const existing = body[key];
        if (Array.isArray(existing)) {
          existing.push(val);
        } else {
          body[key] = [existing, val];
        }
      } else {
        body[key] = val;
      }
    }
    return body;
  }

  return {};
}

async function fetchServices(env) {
  if (!env.DB) return DEFAULT_SERVICES;
  try {
    const result = await env.DB.prepare(
      `SELECT slug, title, summary
       FROM services
       WHERE is_published = 1
       ORDER BY display_order ASC, id ASC`
    ).all();
    return result.results?.length ? result.results : DEFAULT_SERVICES;
  } catch {
    return DEFAULT_SERVICES;
  }
}

async function fetchPosts(env) {
  if (!env.DB) return DEFAULT_POSTS;
  try {
    const result = await env.DB.prepare(
      `SELECT slug, title, excerpt, published_at
       FROM posts
       WHERE is_published = 1
       ORDER BY published_at DESC, id DESC`
    ).all();
    return result.results?.length ? result.results : DEFAULT_POSTS;
  } catch {
    return DEFAULT_POSTS;
  }
}

async function storeContact(env, request, payload) {
  const record = {
    name: firstNonEmpty(payload.name, payload.full_name),
    email: firstNonEmpty(payload.email),
    phone: firstNonEmpty(payload.phone),
    subject: firstNonEmpty(payload.subject),
    message: firstNonEmpty(payload.message, payload.details, payload.project_scope),
    ip: normalizeText(request.headers.get("CF-Connecting-IP") || "", 80),
    user_agent: normalizeText(request.headers.get("User-Agent") || "", 500),
    created_at: new Date().toISOString(),
  };

  if (!record.name || !record.email || !record.message) {
    return { ok: false, status: 400, error: "name, email, and message are required." };
  }
  if (!isEmail(record.email)) {
    return { ok: false, status: 400, error: "invalid email address." };
  }

  if (env.DB) {
    await env.DB.prepare(
      `INSERT INTO contact_submissions
       (name, email, phone, subject, message, ip, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        record.name,
        record.email,
        record.phone,
        record.subject,
        record.message,
        record.ip,
        record.user_agent,
        record.created_at
      )
      .run();
    return { ok: true, status: 201, data: { stored: "d1" } };
  }

  EPHEMERAL_STATE.contacts.push(record);
  return {
    ok: true,
    status: 201,
    data: { stored: "memory", warning: "D1 binding missing; record is not persistent." },
  };
}

async function storeQuote(env, request, payload) {
  const fullName = firstNonEmpty(payload.full_name, payload.name);
  const email = firstNonEmpty(payload.email);
  const primaryService = firstNonEmpty(payload.primary_service_slug, payload.primary_service);
  const businessGoals = firstNonEmpty(payload.business_goals);
  const painPoints = firstNonEmpty(payload.pain_points);

  const detailsBlob = [
    `Project Title: ${firstNonEmpty(payload.project_title) || "Not provided"}`,
    `Primary Service: ${primaryService || "Not provided"}`,
    `Additional Services: ${firstNonEmpty(payload.additional_services) || "None"}`,
    `Business Goals: ${businessGoals || "Not provided"}`,
    `Current Challenges: ${painPoints || "Not provided"}`,
    `Current Environment: ${firstNonEmpty(payload.current_environment) || "Not provided"}`,
    `Integrations: ${firstNonEmpty(payload.integrations) || "Not provided"}`,
    `Additional Notes: ${firstNonEmpty(payload.additional_notes) || "Not provided"}`,
  ].join("\n");

  const record = {
    ticket_number: createTicketNumber(),
    name: fullName,
    email,
    phone: firstNonEmpty(payload.phone),
    company: firstNonEmpty(payload.company),
    primary_service: primaryService,
    budget: firstNonEmpty(payload.budget, payload.budget_range),
    timeline: firstNonEmpty(payload.timeline),
    details: detailsBlob,
    ip: normalizeText(request.headers.get("CF-Connecting-IP") || "", 80),
    user_agent: normalizeText(request.headers.get("User-Agent") || "", 500),
    created_at: new Date().toISOString(),
  };

  if (!record.name || !record.email || !record.primary_service || !businessGoals || !painPoints) {
    return {
      ok: false,
      status: 400,
      error: "full name, email, primary service, business goals, and current challenges are required.",
    };
  }
  if (!isEmail(record.email)) {
    return { ok: false, status: 400, error: "invalid email address." };
  }

  if (env.DB) {
    await env.DB.prepare(
      `INSERT INTO quote_requests
       (ticket_number, name, email, phone, company, primary_service, budget, timeline, details, ip, user_agent, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(
        record.ticket_number,
        record.name,
        record.email,
        record.phone,
        record.company,
        record.primary_service,
        record.budget,
        record.timeline,
        record.details,
        record.ip,
        record.user_agent,
        record.created_at
      )
      .run();
    return { ok: true, status: 201, data: { stored: "d1", ticket_number: record.ticket_number } };
  }

  EPHEMERAL_STATE.quotes.push(record);
  return {
    ok: true,
    status: 201,
    data: {
      stored: "memory",
      ticket_number: record.ticket_number,
      warning: "D1 binding missing; record is not persistent.",
    },
  };
}

function normalizedPath(pathname) {
  const alias = STATIC_ALIASES[pathname];
  if (alias) return alias;
  if (pathname.length > 1 && pathname.endsWith("/")) return pathname.slice(0, -1);
  return pathname;
}

function buildAssetCandidates(pathname) {
  const path = normalizedPath(pathname);
  if (path === "/") return ["/index.html"];

  const candidates = [path];
  if (!path.endsWith(".html") && !path.endsWith(".json") && !path.includes(".", path.lastIndexOf("/") + 1)) {
    candidates.push(`${path}.html`);
  }
  candidates.push(`${path}/index.html`);

  return [...new Set(candidates)];
}

async function serveStatic(request, env) {
  if (!env.ASSETS) {
    return json({ error: "static assets binding missing" }, 500);
  }

  const url = new URL(request.url);
  const candidates = buildAssetCandidates(url.pathname);

  for (const candidate of candidates) {
    const assetUrl = new URL(request.url);
    assetUrl.pathname = candidate;
    const response = await env.ASSETS.fetch(new Request(assetUrl.toString(), request));
    if (response.status !== 404) {
      const headers = new Headers(response.headers);
      headers.set("x-release", RELEASE_ID);
      if (candidate.endsWith(".html") || candidate.endsWith("/index.html")) {
        headers.set("cache-control", "no-store, no-cache, must-revalidate");
      }
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers,
      });
    }
  }

  return new Response("Not found", {
    status: 404,
    headers: {
      "content-type": "text/plain; charset=utf-8",
      "x-release": RELEASE_ID,
      "cache-control": "no-store, no-cache, must-revalidate",
    },
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const pathname = normalizedPath(url.pathname);
    const method = request.method.toUpperCase();

    try {
      if (method === "GET" && pathname === "/version") {
        return json({
          release: RELEASE_ID,
          app: env.APP_NAME || "Right On IT Services",
          mode: env.DB ? "d1" : "memory",
          timestamp: new Date().toISOString(),
        });
      }
      if (method === "GET" && pathname === "/healthz") {
        return json({
          ok: true,
          runtime: "cloudflare-worker-js",
          release: RELEASE_ID,
          timestamp: new Date().toISOString(),
        });
      }

      if (method === "GET" && pathname === "/api/services") {
        return json({ items: await fetchServices(env) });
      }
      if (method === "GET" && pathname === "/api/posts") {
        return json({ items: await fetchPosts(env) });
      }

      if (method === "POST" && (pathname === "/api/contact" || pathname === "/contact")) {
        const result = await storeContact(env, request, await parseBody(request));
        if (!result.ok) {
          if (pathname === "/contact") return formErrorPage("Contact Submission Failed", result.error, result.status);
          return json({ error: result.error }, result.status);
        }
        if (pathname === "/contact") return redirect("/contact?submitted=1");
        return json(result.data, result.status);
      }

      if (method === "POST" && (pathname === "/api/quote" || pathname === "/request-quote")) {
        const result = await storeQuote(env, request, await parseBody(request));
        if (!result.ok) {
          if (pathname === "/request-quote") return formErrorPage("Quote Request Failed", result.error, result.status);
          return json({ error: result.error }, result.status);
        }
        if (pathname === "/request-quote") return redirect(`/request-quote?submitted=1&ticket=${encodeURIComponent(result.data.ticket_number || "")}`);
        return json(result.data, result.status);
      }

      return serveStatic(request, env);
    } catch (error) {
      return json(
        {
          error: "internal server error",
          message: error instanceof Error ? error.message : String(error),
        },
        500
      );
    }
  },
};
