# Deployment and Worker Operation

This document describes recommended ways to run the `securscan` worker so queued scan jobs are processed reliably in production.

## Options

### 1) VM / VPS (recommended)

- Run the web server and worker on the same host with a process manager (`pm2`, `systemd`). Use a persistent filesystem for `data/securscan.db`.

Example with `pm2`:

```bash
# install deps
npm ci

# start web server
pm2 start npm --name securscan -- start

# start worker
pm2 start npm --name securscan-worker -- run worker

# monitor
pm2 logs securscan-worker
```

### 2) Vercel / Serverless (no persistent process)

- Use Vercel Scheduled Functions or an external scheduler to invoke `/api/worker/run` every X minutes. This endpoint processes a single pending job per invocation and is designed to be idempotent.

Example Vercel Cron flow:

1. Create a Vercel Project Cron Job to call `https://<your-deployment>/api/worker/run` every 5 minutes.
2. Add a secret token check (recommended) to the endpoint and include it as a header in the cron invocation.

Notes:
- Serverless functions have limited execution time — ensure scan timeouts are conservative and prefer short scan slices when running via scheduler.
- For heavy scanning workloads, prefer a VM or managed container.

### 3) GitHub Actions / External Scheduler

- You can create a GitHub Action scheduled workflow to call `/api/worker/run` periodically. This is useful if you don't have Vercel Cron.
