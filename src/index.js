const DEFAULT_SERVICES = [
  {
    slug: "managed-it-services",
    title: "Managed IT Services",
    summary: "24/7 monitoring, patching, endpoint management, and help desk operations.",
  },
  {
    slug: "cybersecurity",
    title: "Cybersecurity",
    summary: "Risk reduction through endpoint protection, identity controls, and security hardening.",
  },
  {
    slug: "cloud-migration",
    title: "Cloud Migration",
    summary: "Move critical workloads to modern cloud infrastructure with rollback-safe planning.",
  },
  {
    slug: "computer-repair",
    title: "Computer Repair",
    summary: "Business laptop and desktop diagnostics, hardware repair, and stabilization.",
  },
];

const DEFAULT_POSTS = [
  {
    slug: "building-a-practical-security-baseline",
    title: "Building a Practical Security Baseline",
    excerpt: "A pragmatic way to reduce incident risk in SMB environments.",
    published_at: "2026-02-01T12:00:00.000Z",
  },
  {
    slug: "choosing-managed-services-vs-in-house-it",
    title: "Managed Services vs In-House IT",
    excerpt: "How to decide based on cost, response time, and operational complexity.",
    published_at: "2026-01-20T12:00:00.000Z",
  },
];

const EPHEMERAL_STATE = {
  contacts: [],
  quotes: [],
};

function json(payload, status = 200) {
  return new Response(JSON.stringify(payload, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
  });
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function normalizeText(value, max = 2000) {
  return String(value ?? "").trim().slice(0, max);
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value ?? "").trim());
}

function formatDate(isoString) {
  try {
    return new Date(isoString).toLocaleDateString("en-US", {
      year: "numeric",
      month: "short",
      day: "2-digit",
    });
  } catch {
    return isoString;
  }
}

function layout(title, body) {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${escapeHtml(title)}</title>
  <style>
    :root {
      --bg: #f5f7fb;
      --surface: #ffffff;
      --text: #1a2230;
      --muted: #5f6b7a;
      --line: #d9e0ea;
      --brand: #0c4a6e;
      --brand-2: #0f766e;
      --ok: #166534;
      --bad: #b91c1c;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: "Segoe UI", "Helvetica Neue", Helvetica, Arial, sans-serif;
      color: var(--text);
      background:
        radial-gradient(circle at 0% 0%, #e9f4ff, transparent 40%),
        radial-gradient(circle at 100% 0%, #dff8f3, transparent 30%),
        var(--bg);
    }
    header {
      border-bottom: 1px solid var(--line);
      background: linear-gradient(135deg, #0b3a59, #0f766e);
      color: #fff;
    }
    .shell { max-width: 1000px; margin: 0 auto; padding: 0 20px; }
    .topbar { display: flex; gap: 14px; align-items: center; padding: 16px 0; flex-wrap: wrap; }
    .brand { font-weight: 700; letter-spacing: 0.2px; }
    nav { display: flex; gap: 12px; flex-wrap: wrap; }
    nav a { color: #d9f1ff; text-decoration: none; font-weight: 600; font-size: 14px; }
    nav a:hover { color: #fff; text-decoration: underline; }
    main { padding: 26px 0 36px; }
    .card {
      background: var(--surface);
      border: 1px solid var(--line);
      border-radius: 14px;
      padding: 16px;
      box-shadow: 0 8px 28px rgba(15, 23, 42, 0.05);
    }
    .grid { display: grid; gap: 14px; }
    .grid-2 { grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); }
    h1 { margin: 0 0 12px; font-size: 30px; line-height: 1.15; }
    h2 { margin: 0 0 10px; font-size: 20px; }
    p { margin: 0 0 10px; color: var(--muted); }
    .btn {
      border: 0;
      border-radius: 10px;
      padding: 10px 14px;
      font-weight: 700;
      cursor: pointer;
      background: linear-gradient(135deg, var(--brand), var(--brand-2));
      color: #fff;
    }
    label { display: block; font-size: 13px; font-weight: 700; margin: 12px 0 6px; }
    input, textarea {
      width: 100%;
      border: 1px solid var(--line);
      border-radius: 10px;
      padding: 10px 11px;
      font: inherit;
      background: #fff;
    }
    textarea { min-height: 120px; resize: vertical; }
    .status { margin-top: 10px; font-weight: 600; min-height: 20px; }
    .ok { color: var(--ok); }
    .bad { color: var(--bad); }
    .meta { font-size: 12px; color: var(--muted); }
    footer { border-top: 1px solid var(--line); padding: 18px 0 26px; color: var(--muted); font-size: 13px; }
    code.inline { padding: 2px 6px; border-radius: 6px; background: #eef3f9; }
  </style>
</head>
<body>
  <header>
    <div class="shell topbar">
      <div class="brand">Right On IT Services</div>
      <nav>
        <a href="/">Home</a>
        <a href="/services">Services</a>
        <a href="/blog">Blog</a>
        <a href="/contact">Contact</a>
        <a href="/request-quote">Request Quote</a>
        <a href="/healthz">Health</a>
      </nav>
    </div>
  </header>
  <main>
    <div class="shell">${body}</div>
  </main>
  <footer>
    <div class="shell">Cloudflare Worker rewrite (JS + optional D1/R2) running successfully.</div>
  </footer>
</body>
</html>`;
}

function page(title, body, status = 200) {
  return new Response(layout(title, body), {
    status,
    headers: { "content-type": "text/html; charset=utf-8" },
  });
}

function servicesMarkup(services) {
  return services
    .map(
      (service) => `
      <article class="card">
        <h2>${escapeHtml(service.title)}</h2>
        <p>${escapeHtml(service.summary)}</p>
        <div class="meta">Slug: <code class="inline">${escapeHtml(service.slug)}</code></div>
      </article>
    `
    )
    .join("");
}

function postsMarkup(posts) {
  return posts
    .map(
      (post) => `
      <article class="card">
        <h2>${escapeHtml(post.title)}</h2>
        <p>${escapeHtml(post.excerpt)}</p>
        <div class="meta">
          Published: ${escapeHtml(formatDate(post.published_at))}
          · Slug: <code class="inline">${escapeHtml(post.slug)}</code>
        </div>
      </article>
    `
    )
    .join("");
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
      body[key] = typeof value === "string" ? value : String(value ?? "");
    }
    return body;
  }
  return {};
}

async function fetchServices(env) {
  if (!env.DB) return DEFAULT_SERVICES;
  const query = `
    SELECT slug, title, summary
    FROM services
    WHERE is_published = 1
    ORDER BY display_order ASC, id ASC
  `;
  try {
    const result = await env.DB.prepare(query).all();
    if (!result.results?.length) return DEFAULT_SERVICES;
    return result.results;
  } catch {
    return DEFAULT_SERVICES;
  }
}

async function fetchPosts(env) {
  if (!env.DB) return DEFAULT_POSTS;
  const query = `
    SELECT slug, title, excerpt, published_at
    FROM posts
    WHERE is_published = 1
    ORDER BY published_at DESC, id DESC
  `;
  try {
    const result = await env.DB.prepare(query).all();
    if (!result.results?.length) return DEFAULT_POSTS;
    return result.results;
  } catch {
    return DEFAULT_POSTS;
  }
}

function createTicketNumber() {
  const stamp = new Date().toISOString().replace(/\D/g, "").slice(0, 14);
  const token = crypto.randomUUID().split("-")[0].toUpperCase();
  return `RS-${stamp}-${token}`;
}

async function storeContact(env, request, payload) {
  const record = {
    name: normalizeText(payload.name, 120),
    email: normalizeText(payload.email, 200),
    phone: normalizeText(payload.phone, 80),
    subject: normalizeText(payload.subject, 220),
    message: normalizeText(payload.message, 5000),
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
    const sql = `
      INSERT INTO contact_submissions
      (name, email, phone, subject, message, ip, user_agent, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `;
    await env.DB.prepare(sql)
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
  const record = {
    ticket_number: createTicketNumber(),
    name: normalizeText(payload.name, 120),
    email: normalizeText(payload.email, 200),
    phone: normalizeText(payload.phone, 80),
    company: normalizeText(payload.company, 200),
    primary_service: normalizeText(payload.primary_service, 160),
    budget: normalizeText(payload.budget, 160),
    timeline: normalizeText(payload.timeline, 160),
    details: normalizeText(payload.details || payload.message, 6000),
    ip: normalizeText(request.headers.get("CF-Connecting-IP") || "", 80),
    user_agent: normalizeText(request.headers.get("User-Agent") || "", 500),
    created_at: new Date().toISOString(),
  };

  if (!record.name || !record.email || !record.primary_service || !record.details) {
    return {
      ok: false,
      status: 400,
      error: "name, email, primary_service, and details are required.",
    };
  }
  if (!isEmail(record.email)) {
    return { ok: false, status: 400, error: "invalid email address." };
  }

  if (env.DB) {
    const sql = `
      INSERT INTO quote_requests
      (ticket_number, name, email, phone, company, primary_service, budget, timeline, details, ip, user_agent, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    await env.DB.prepare(sql)
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

function contactPage() {
  return page(
    "Contact",
    `
    <section class="card">
      <h1>Contact Us</h1>
      <p>Submit operational or service inquiries. This Cloudflare rewrite writes to D1 when binding <code class="inline">DB</code> is configured.</p>
      <form id="contact-form">
        <label>Name</label>
        <input name="name" required />
        <label>Email</label>
        <input type="email" name="email" required />
        <label>Phone</label>
        <input name="phone" />
        <label>Subject</label>
        <input name="subject" />
        <label>Message</label>
        <textarea name="message" required></textarea>
        <button class="btn" type="submit">Send Message</button>
        <div id="status" class="status"></div>
      </form>
    </section>
    <script>
      const form = document.getElementById("contact-form");
      const status = document.getElementById("status");
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        status.className = "status";
        status.textContent = "Submitting...";
        const body = Object.fromEntries(new FormData(form).entries());
        const res = await fetch("/api/contact", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (res.ok) {
          status.classList.add("ok");
          status.textContent = "Message submitted.";
          form.reset();
        } else {
          status.classList.add("bad");
          status.textContent = data.error || "Submission failed.";
        }
      });
    </script>
  `
  );
}

function quotePage() {
  return page(
    "Request Quote",
    `
    <section class="card">
      <h1>Request a Quote</h1>
      <p>Open a new quote intake request. On success we return a generated ticket number.</p>
      <form id="quote-form">
        <label>Name</label>
        <input name="name" required />
        <label>Email</label>
        <input type="email" name="email" required />
        <label>Phone</label>
        <input name="phone" />
        <label>Company</label>
        <input name="company" />
        <label>Primary Service</label>
        <input name="primary_service" required />
        <label>Budget</label>
        <input name="budget" />
        <label>Timeline</label>
        <input name="timeline" />
        <label>Details</label>
        <textarea name="details" required></textarea>
        <button class="btn" type="submit">Submit Quote Request</button>
        <div id="status" class="status"></div>
      </form>
    </section>
    <script>
      const form = document.getElementById("quote-form");
      const status = document.getElementById("status");
      form.addEventListener("submit", async (e) => {
        e.preventDefault();
        status.className = "status";
        status.textContent = "Submitting...";
        const body = Object.fromEntries(new FormData(form).entries());
        const res = await fetch("/api/quote", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(body)
        });
        const data = await res.json();
        if (res.ok) {
          status.classList.add("ok");
          status.textContent = "Quote submitted. Ticket: " + (data.ticket_number || "created");
          form.reset();
        } else {
          status.classList.add("bad");
          status.textContent = data.error || "Submission failed.";
        }
      });
    </script>
  `
  );
}

async function homePage(env) {
  const [services, posts] = await Promise.all([fetchServices(env), fetchPosts(env)]);
  return page(
    "Right On IT Services",
    `
    <section class="card">
      <h1>Cloudflare-Native Rewrite</h1>
      <p>This deployment runs on a JavaScript Worker and no longer relies on Python Worker package support.</p>
      <p>Core forms and content APIs are D1-backed when <code class="inline">DB</code> binding exists.</p>
    </section>
    <div style="height: 14px"></div>
    <section>
      <h2>Featured Services</h2>
      <div class="grid grid-2">${servicesMarkup(services.slice(0, 4))}</div>
    </section>
    <div style="height: 14px"></div>
    <section>
      <h2>Latest Posts</h2>
      <div class="grid">${postsMarkup(posts.slice(0, 3))}</div>
    </section>
  `
  );
}

async function servicesPage(env) {
  const services = await fetchServices(env);
  return page(
    "Services",
    `
    <section>
      <h1>Services</h1>
      <p>Service catalog rendered from D1 when available, with safe in-code defaults as fallback.</p>
      <div class="grid grid-2">${servicesMarkup(services)}</div>
    </section>
  `
  );
}

async function blogPage(env) {
  const posts = await fetchPosts(env);
  return page(
    "Blog",
    `
    <section>
      <h1>Blog</h1>
      <p>Operational notes and field updates.</p>
      <div class="grid">${postsMarkup(posts)}</div>
    </section>
  `
  );
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const { pathname } = url;
    const method = request.method.toUpperCase();

    try {
      if (method === "GET" && pathname === "/healthz") {
        return json({ ok: true, runtime: "cloudflare-worker-js", timestamp: new Date().toISOString() });
      }

      if (method === "GET" && pathname === "/api/services") {
        return json({ items: await fetchServices(env) });
      }
      if (method === "GET" && pathname === "/api/posts") {
        return json({ items: await fetchPosts(env) });
      }
      if (method === "POST" && pathname === "/api/contact") {
        const result = await storeContact(env, request, await parseBody(request));
        if (!result.ok) return json({ error: result.error }, result.status);
        return json(result.data, result.status);
      }
      if (method === "POST" && pathname === "/api/quote") {
        const result = await storeQuote(env, request, await parseBody(request));
        if (!result.ok) return json({ error: result.error }, result.status);
        return json(result.data, result.status);
      }

      if (method === "GET" && pathname === "/") return await homePage(env);
      if (method === "GET" && pathname === "/services") return await servicesPage(env);
      if (method === "GET" && pathname === "/blog") return await blogPage(env);
      if (method === "GET" && pathname === "/contact") return contactPage();
      if (method === "GET" && pathname === "/request-quote") return quotePage();

      return page(
        "Not Found",
        `
        <section class="card">
          <h1>404</h1>
          <p>The route <code class="inline">${escapeHtml(pathname)}</code> was not found.</p>
        </section>
      `,
        404
      );
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
