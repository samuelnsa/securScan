#!/usr/bin/env node
import { setTimeout } from 'node:timers/promises';
import { db } from './db.js';
import { getJob } from './storage.js';
import { getOrCreateSite, getLastScanForSite, saveScan, updateJobStarted, completeJobSuccess, completeJobFailure } from './storage.js';
import { scanTarget } from '../scanner/index.js';
import { analyzeRegression } from './regression.js';

async function fetchPendingJob() {
  const row = db.prepare("SELECT * FROM jobs WHERE status = 'PENDING' ORDER BY created_at ASC LIMIT 1").get();
  return row;
}

async function processJob(job) {
  const jobId = job.id;
  try {
    updateJobStarted(jobId);
    const siteId = job.site_id || (getOrCreateSite(job.url) || {}).id;
    const previousScan = getLastScanForSite(siteId);
    const report = await scanTarget(job.url, { timeout: 60000, sslTimeout: 15000 });
    const regression = analyzeRegression(previousScan, report);
    const { scanId } = saveScan(siteId, report, regression);
    completeJobSuccess(jobId, scanId, report);
    console.log(`Job ${jobId} completed -> scan ${scanId}`);
  } catch (err) {
    console.error(`Job ${jobId} failed:`, err && err.stack ? err.stack : err);
    completeJobFailure(jobId, err?.message || String(err));
  }
}

async function runWorkerLoop() {
  console.log('Worker started, polling for pending jobs...');
  while (true) {
    const job = await fetchPendingJob();
    if (!job) {
      await setTimeout(3000);
      continue;
    }
    await processJob(job);
  }
}

if (process.argv[1] && process.argv[1].endsWith('worker.js')) {
  runWorkerLoop().catch(err => {
    console.error('Worker fatal:', err);
    process.exit(1);
  });
}
