/*
 * Copyright 2024 Adobe. All rights reserved.
 * This file is licensed to you under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under
 * the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS
 * OF ANY KIND, either express or implied. See the License for the specific language
 * governing permissions and limitations under the License.
 */

import assert from 'assert';
import worker from '../src/index.js';

const WORKER_HOST = 'https://rum-proxy-ci.adobeaem.workers.dev';
const ORIGIN_HOST = 'main--helix-website--adobe.aem.live';

const EXPLORER_HTML = '<html><head><title>RUM Explorer</title></head><body></body></html>';

describe('index tests', () => {
  /** @type {typeof globalThis.fetch} */
  let originalFetch;
  /** @type {Array<string>} */
  let fetched;
  /** @type {(url: URL) => Response} */
  let respond;

  const ctx = { waitUntil: () => {} };

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    fetched = [];
    respond = () => new Response('not found', { status: 404 });
    globalThis.fetch = async (input) => {
      const url = new URL(input instanceof Request ? input.url : String(input));
      fetched.push(url.href);
      return respond(url);
    };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  describe('paths outside /tools/rum/', () => {
    ['/', '/docs/', '/developer/tutorial', '/tools/rum', '/tools/rumx', '/tools/', '/TOOLS/rum/explorer.html'].forEach((path) => {
      it(`redirects ${path} to www.aem.live without calling the origin`, async () => {
        const resp = await worker.fetch(new Request(`${WORKER_HOST}${path}`), {}, ctx);
        assert.strictEqual(resp.status, 301);
        assert.strictEqual(resp.headers.get('location'), `https://www.aem.live${path}`);
        assert.strictEqual(await resp.text(), '');
        assert.deepStrictEqual(fetched, []);
      });
    });

    it('keeps path and query in the redirect', async () => {
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/docs/setup?a=1&b=two%20words`), {}, ctx);
      assert.strictEqual(resp.status, 301);
      assert.strictEqual(resp.headers.get('location'), 'https://www.aem.live/docs/setup?a=1&b=two%20words');
      assert.deepStrictEqual(fetched, []);
    });

    it('does not serve any branded site content', async () => {
      respond = () => new Response('<html><head><title>Adobe Experience Manager</title></head></html>', {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/`), {}, ctx);
      assert.strictEqual(resp.status, 301);
      assert.ok(!(await resp.text()).includes('Adobe'));
      assert.deepStrictEqual(fetched, []);
    });
  });

  describe('/tools/rum/explorer.html', () => {
    it('still proxies to the origin and adds og meta tags', async () => {
      respond = () => new Response(EXPLORER_HTML, {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/explorer.html?domain=www.example.com&view=week`), {}, ctx);
      assert.strictEqual(resp.status, 200);
      assert.strictEqual(fetched.length, 1);
      const upstream = new URL(fetched[0]);
      assert.strictEqual(upstream.hostname, ORIGIN_HOST);
      assert.strictEqual(upstream.pathname, '/tools/rum/explorer.html');
      const html = await resp.text();
      assert.ok(html.includes('<meta property="og:site_name" content="RUM Explorer" />'));
      assert.ok(html.includes('<meta property="og:title" content="RUM Data for www.example.com" />'));
      assert.ok(html.includes('<meta property="og:description" content="Weekly RUM data for www.example.com" />'));
      assert.ok(html.includes('https://www.aem.live/tools/rum/_ogimage?domain=www.example.com&amp;view=week')
        || html.includes('https://www.aem.live/tools/rum/_ogimage?domain=www.example.com&view=week'));
    });

    it('escapes parameters in og meta tags', async () => {
      respond = () => new Response(EXPLORER_HTML, { status: 200 });
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/explorer.html?domain=${encodeURIComponent('"><script>x</script>')}`), {}, ctx);
      const html = await resp.text();
      assert.ok(!html.includes('<script>x</script>'));
      assert.ok(html.includes('&quot;&gt;&lt;script&gt;x&lt;/script&gt;'));
    });

    it('passes through non-ok origin responses', async () => {
      respond = () => new Response('gone', { status: 404 });
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/explorer.html`), {}, ctx);
      assert.strictEqual(resp.status, 404);
      assert.strictEqual(fetched.length, 1);
    });
  });

  describe('other /tools/rum/ assets', () => {
    it('are proxied from the origin unchanged', async () => {
      respond = () => new Response('export default 1;', {
        status: 200,
        headers: { 'content-type': 'application/javascript' },
      });
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/elements/list-facet.js?v=1`), {}, ctx);
      assert.strictEqual(resp.status, 200);
      assert.strictEqual(await resp.text(), 'export default 1;');
      assert.strictEqual(fetched.length, 1);
      const upstream = new URL(fetched[0]);
      assert.strictEqual(upstream.hostname, ORIGIN_HOST);
      assert.strictEqual(upstream.pathname, '/tools/rum/elements/list-facet.js');
      assert.strictEqual(upstream.search, '?v=1');
    });
  });

  describe('/tools/rum/_cors', () => {
    it('returns 400 for a missing url', async () => {
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/_cors`), {}, ctx);
      assert.strictEqual(resp.status, 400);
      assert.strictEqual(resp.headers.get('x-error'), 'invalid url');
      assert.deepStrictEqual(fetched, []);
    });

    it('returns 403 for an invalid domainkey', async () => {
      const target = 'https://www.example.com/data.json';
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/_cors?url=${encodeURIComponent(target)}&domainkey=bad`), {}, ctx);
      assert.strictEqual(resp.status, 403);
      assert.strictEqual(resp.headers.get('x-error'), 'invalid domainkey');
      assert.strictEqual(fetched.length, 1);
      assert.ok(fetched[0].startsWith('https://bundles.aem.page/domains/www.example.com'));
    });

    it('proxies the target with CORS headers for a valid domainkey', async () => {
      const target = 'https://www.example.com/data.json';
      respond = (url) => {
        if (url.hostname === 'bundles.aem.page') {
          return new Response('{}', { status: 200 });
        }
        return new Response('{"ok":true}', {
          status: 200,
          headers: { 'content-type': 'application/json' },
        });
      };
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/_cors?url=${encodeURIComponent(target)}&domainkey=good`), {}, ctx);
      assert.strictEqual(resp.status, 200);
      assert.strictEqual(resp.headers.get('access-control-allow-origin'), '*');
      assert.strictEqual(await resp.text(), '{"ok":true}');
      assert.deepStrictEqual(fetched.map((u) => new URL(u).hostname), ['bundles.aem.page', 'www.example.com']);
    });
  });

  describe('/tools/rum/_ogimage', () => {
    it('returns 400 for missing domain or view', async () => {
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/_ogimage`), {}, ctx);
      assert.strictEqual(resp.status, 400);
      assert.strictEqual(resp.headers.get('x-error'), 'missing domain or view');
      assert.deepStrictEqual(fetched, []);
    });

    it('serves a stored image from the bucket', async () => {
      const keys = [];
      const env = {
        IMAGE_BUCKET: {
          head: async (key) => {
            keys.push(key);
            return { customMetadata: { state: 'loaded' } };
          },
          get: async () => ({
            arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer,
            httpMetadata: { contentType: 'image/jpeg' },
          }),
        },
      };
      const resp = await worker.fetch(new Request(`${WORKER_HOST}/tools/rum/_ogimage?view=week&domain=www.example.com`), env, ctx);
      assert.strictEqual(resp.status, 200);
      assert.strictEqual(resp.headers.get('content-type'), 'image/jpeg');
      assert.deepStrictEqual(keys, ['images/www.example.com/week/domain=www.example.com&view=week']);
      assert.deepStrictEqual(fetched, []);
    });

    it('redirects to the default image while a screenshot is pending', async () => {
      const waited = [];
      const env = {
        IMAGE_BUCKET: {
          head: async () => ({ customMetadata: { state: 'pending' } }),
        },
      };
      const resp = await worker.fetch(
        new Request(`${WORKER_HOST}/tools/rum/_ogimage?view=week&domain=www.example.com`),
        env,
        { waitUntil: (p) => waited.push(p) },
      );
      assert.strictEqual(resp.status, 302);
      assert.ok(resp.headers.get('location').startsWith('https://www.aem.live/default-social.png'));
      assert.strictEqual(waited.length, 1);
      await waited[0];
    });
  });
});
