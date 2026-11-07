# BLUE SOC · AI Security Operations Center

This is the **standalone BLUE SOC website** for the BYUI CIT security lab (P8). It is separate from the Salone Aegis network-architecture project. The frontend is intentionally read-only unless an administrator explicitly authenticates and requests a workflow.

## What changed

- Preserves the dark BLUE SOC design, event feed, simulated workflow diagram, incident indicators and AI chat layout.
- **Demo mode** is the default. Its examples use documentation-only IPs, are labeled DEMO and do not perform live actions.
- **Authenticated mode** requests data from the website's own `/api/soc` function, which reads JSONBin server-side. No JSONBin API key, direct webhook or administrator token is compiled into the browser.
- All messages, event fields and blocking records use DOM `textContent`, not injected untrusted HTML. Unknown data is bounded by the API.
- Service badges no longer assert N8N/Splunk/AI are live just because the web page opened.
- A manual scan request requires an authenticated admin, an explicit confirmation in the browser, `BLUE_SOC_ALLOW_SCAN=true`, and a configured server-side n8n scan URL. An accepted request is not proof a firewall block was applied.
- Supports narrow screens, keyboard focus, reduced motion preferences and a locally cleared feed (without deleting upstream records).

## Security action required before production

**Rotate the old JSONBin master key immediately.** A key was embedded in a publicly accessible version of `index.html`; removing it from the current file does not remove it from Git history or revoke it. Reissue the key at JSONBin, revoke the compromised key, and review the bin's records and access logs as appropriate. Prefer creating a **read-only** JSONBin Access Key restricted to the needed bin. Never put credentials in public JavaScript, a GitHub commit, or a screenshot.

Do not rely on the old public `trycloudflare.com` tunnel URLs. Replace them with stable, access-controlled HTTPS n8n webhook endpoints. Keep n8n and the Palo Alto management API private and use allowlists, human approvals and rollback procedures for any security-policy changes.

## Deploy on Vercel

1. Import this `kamara1994/bluesoc` repository into a Vercel project. Deploy the branch for preview or merge the pull request once reviewed.
2. In **Project Settings → Environment Variables**, configure the variables below for the intended deployment environment. Choose the **Secret** value type where supported.
3. Redeploy after changing environment variables. Open the site, choose **CONFIG**, and enter the `BLUE_SOC_ADMIN_TOKEN` value. It is held in memory for that tab and not stored in localStorage.
4. Verify telemetry counts and records against the actual source, test chat with a harmless prompt, then test a scan **only after** lab authorization and firewall rollback safeguards are confirmed.

| Variable | Required | Meaning |
| --- | --- | --- |
| `BLUE_SOC_ADMIN_TOKEN` | Yes | Unique high-entropy random token, at least 24 characters, to access private telemetry and actions. |
| `BLUE_SOC_JSONBIN_ID` | Yes, for telemetry | The record ID for the JSONBin containing authorized events. |
| `BLUE_SOC_JSONBIN_READ_KEY` | Strongly preferred | A read-only scoped access key that stays server-side. |
| `BLUE_SOC_JSONBIN_MASTER_KEY` | Alternative only | Newly rotated master key on the server only. Never use the exposed old value. |
| `BLUE_SOC_CHAT_WEBHOOK` | For AI chat | Stable HTTPS backend n8n chat webhook, ideally protected by additional n8n-side access controls. |
| `BLUE_SOC_SCAN_WEBHOOK` | For scan request | Stable HTTPS backend n8n scan webhook. |
| `BLUE_SOC_ALLOW_SCAN` | Optional | Set to `true` only once the end-to-end containment flow is safe and approved. Defaults to disabled. |

Vercel automatically handles Node.js functions in the root `api/` folder. Running a plain static file server shows the demo page, but authenticated `/api/soc` requests will only work when the serverless backend is running. Locally, use Vercel's development environment if you need to exercise backend requests.

## Checks

Requires Node.js 20 or newer.

```bash
npm run check
```

The checks verify JavaScript syntax and the API's authentication and request-validation behavior. Real live system verification is separate and must be performed with lab credentials and authorized infrastructure.

## Data format

The n8n workflow can continue writing JSONBin records such as:

```json
{
  "events": [
    {
      "event_type": "rigby_url_alert",
      "timestamp": "2026-11-06T19:00:00Z",
      "severity": "high",
      "message": "Approved test URL matched",
      "source_ip": "198.51.100.23",
      "dest_ip": "192.0.2.10"
    }
  ],
  "blocked_ips": [
    {
      "ip": "198.51.100.23",
      "reason": "Upstream reported temporary block",
      "time": "2026-11-06T19:01:00Z"
    }
  ],
  "runs": 1,
  "last_run": "2026-11-06T19:01:00Z",
  "analysis": {
    "threat_level": "high",
    "offending_ip": "198.51.100.23",
    "activity": "Test event for controlled response"
  }
}
```

The dashboard displays an upstream **reported** block, not independently verified Palo Alto rule state. For rigorous evidence, cross-check the firewall logs, block-list entries, action timestamp and rollback.

## Note on deployment

This code can be prepared through the GitHub connector, but it does not automatically update your publicly hosted domain. Confirm which repository is linked in Vercel, set the server secrets, then deploy the change. The similarly named `blue-dashboard-v3.0` repository is a separate **Career OS** website and should not be substituted for the BLUE SOC security operations application.
