# MCP Services Research + Implementation Notes (2026-02-23)

## Scope
Identify 10 additional MCP services relevant to a website + CMS + dashboard operations stack, then wire the platform to support approval, execution, retry, and audit for MCP tool calls.

## Primary Sources
- Model Context Protocol reference servers repository (official): https://github.com/modelcontextprotocol/servers
- Cloudflare official MCP integration list: https://developers.cloudflare.com/agents/model-context-protocol/mcp-servers/

## 10 Additional MCP Services You Can Use

1. Filesystem MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/filesystem
- Use case: content/template file automation, media manifest checks, batch content ops.

2. Fetch MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/fetch
- Use case: ingest competitor pages, docs, and external metadata into CMS workflows.

3. Git MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/git
- Use case: audit config changes, release notes, branch quality checks.

4. GitHub MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/github
- Use case: PR monitoring, issue triage, deployment pipeline governance.

5. GitLab MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/gitlab
- Use case: teams using GitLab CI/CD and issue management.

6. Google Drive MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/gdrive
- Use case: sync briefs, SOPs, and client docs into operations workflows.

7. PostgreSQL MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/postgres
- Use case: controlled analytics and dataset queries for dashboards.

8. Puppeteer MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/puppeteer
- Use case: visual QA automation, screenshot checks, smoke testing web pages.

9. Slack MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/slack
- Use case: incident alerts, support escalation messaging, ops notifications.

10. SQLite MCP
- Source: https://github.com/modelcontextprotocol/servers/tree/main/src/sqlite
- Use case: local/stage diagnostics and quick data validation tasks.

## Related Production-Grade Hosted MCP Options
- Context7: https://mcp.context7.com/mcp
- Cloudflare docs MCP: https://docs.mcp.cloudflare.com/
- DeepWiki MCP: https://mcp.deepwiki.com/mcp

## What Was Implemented In This Repo
- MCP operation queue model with statuses, approval state, retries, and execution traces.
- MCP Operations admin UI for creating/approving/running/retrying calls.
- MCP Operations API endpoint for live status consumption.
- Queue processing action for bulk execution of due jobs.
- Seeded MCP server templates (disabled by default) for the 10 services listed above.

## Activation Guidance
- Keep templates disabled until each server endpoint is deployed and authenticated.
- Start with `require_approval=always` and narrow allowed tools per server.
- Move to `selective` only after audit logs prove stable behavior.
