import request from 'supertest';
import { app } from '../src/server/index.js';
import { strict as assert } from 'assert';

describe('Security headers', function() {
  it('should include CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy', async function() {
    const res = await request(app).get('/api/summary');
    assert.ok(res.headers['content-security-policy'], 'CSP missing');
    assert.ok(res.headers['x-frame-options'] || res.headers['content-security-policy'].includes('frame-ancestors'), 'X-Frame-Options/frame-ancestors missing');
    assert.equal(res.headers['x-content-type-options'], 'nosniff');
    assert.equal(res.headers['referrer-policy'], 'strict-origin-when-cross-origin');
    assert.ok(res.headers['permissions-policy'], 'Permissions-Policy missing');
  });
});
