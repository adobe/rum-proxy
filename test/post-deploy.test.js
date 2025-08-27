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
import { config } from 'dotenv';

config();

// Determine the deployment environment
const ENVIRONMENT = process.env.ENVIRONMENT || 'ci';
const TEST_DOMAIN = ENVIRONMENT === 'production'
  ? 'www.aem.live'
  : 'rum-proxy-ci.adobeaem.workers.dev';

describe('Post-Deploy Tests', () => {
  describe('RUM Explorer OpenGraph Meta Tags XSS Prevention', () => {
    const explorerPath = '/tools/rum/explorer.html';

    it('should escape XSS in filter parameter', async () => {
      const xssPayload = '"><img src=x onerror=alert(5)>';
      const url = `https://${TEST_DOMAIN}${explorerPath}?filter=${encodeURIComponent(xssPayload)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Check that the payload is properly escaped in meta tags
      assert.ok(
        !html.includes('"><img src=x onerror=alert(5)>'),
        'Raw XSS payload should not appear in HTML',
      );

      assert.ok(
        html.includes('&quot;&gt;&lt;img src=x onerror=alert(5)&gt;'),
        'XSS payload should be HTML-escaped in meta tags',
      );

      // Ensure og:description meta tag exists
      assert.ok(
        html.includes('property="og:description"'),
        'Should contain og:description meta tag',
      );
    });

    it('should escape XSS in domain parameter', async () => {
      const xssPayload = '"><script>alert(document.cookie)</script>';
      const url = `https://${TEST_DOMAIN}${explorerPath}?domain=${encodeURIComponent(xssPayload)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Check that script tags are escaped
      assert.ok(
        !html.includes('<script>alert(document.cookie)</script>'),
        'Script tags should not execute',
      );

      assert.ok(
        html.includes('&quot;&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;'),
        'Script tags should be HTML-escaped',
      );

      // Check both og:title and og:description
      assert.ok(
        html.includes('property="og:title"'),
        'Should contain og:title meta tag',
      );
    });

    it('should escape XSS in checkpoint parameter', async () => {
      const xssPayload = '\' onmouseover=\'alert(1)\'';
      const url = `https://${TEST_DOMAIN}${explorerPath}?checkpoint=${encodeURIComponent(xssPayload)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Check that event handlers are escaped
      assert.ok(
        !html.includes('onmouseover=\'alert(1)\''),
        'Event handlers should not be present',
      );

      assert.ok(
        html.includes('&#039; onmouseover=&#039;alert(1)&#039;')
        || html.includes('&amp;#039; onmouseover=&amp;#039;alert(1)&amp;#039;'),
        'Event handlers should be HTML-escaped',
      );
    });

    it('should escape XSS in view parameter', async () => {
      const xssPayload = '"><svg onload=alert(1)>';
      const url = `https://${TEST_DOMAIN}${explorerPath}?view=${encodeURIComponent(xssPayload)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Check that SVG tags are escaped
      assert.ok(
        !html.includes('<svg onload=alert(1)>'),
        'SVG tags should not execute',
      );
    });

    it('should handle multiple XSS parameters simultaneously', async () => {
      const domain = '"><script>alert(1)</script>';
      const filter = '"><img src=x onerror=alert(2)>';
      const checkpoint = '\' onmouseover=\'alert(3)\'';

      const url = `https://${TEST_DOMAIN}${explorerPath}?domain=${encodeURIComponent(domain)}&filter=${encodeURIComponent(filter)}&checkpoint=${encodeURIComponent(checkpoint)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // None of the XSS payloads should be executable
      assert.ok(
        !html.includes('<script>alert(1)</script>'),
        'Script tag from domain should be escaped',
      );
      assert.ok(
        !html.includes('"><img src=x onerror=alert(2)>'),
        'Image tag from filter should be escaped',
      );
      assert.ok(
        !html.includes('onmouseover=\'alert(3)\''),
        'Event handler from checkpoint should be escaped',
      );

      // All should be properly escaped
      assert.ok(
        html.includes('&lt;script&gt;') && html.includes('&lt;/script&gt;'),
        'Script tags should be escaped with HTML entities',
      );
    });

    it('should preserve safe content in parameters', async () => {
      const safeDomain = 'www.example.com';
      const safeFilter = 'pageviews > 100';
      const url = `https://${TEST_DOMAIN}${explorerPath}?domain=${safeDomain}&filter=${encodeURIComponent(safeFilter)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Safe content should appear normally
      assert.ok(
        html.includes('www.example.com'),
        'Safe domain should appear unmodified',
      );

      // The greater-than sign in filter should be escaped for safety
      assert.ok(
        html.includes('pageviews &gt; 100'),
        'Greater-than sign should be escaped',
      );
    });

    it('should handle empty and null-like parameters gracefully', async () => {
      const url = `https://${TEST_DOMAIN}${explorerPath}?domain=&filter=null&checkpoint=undefined`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Should have valid OpenGraph tags even with empty parameters
      assert.ok(
        html.includes('property="og:site_name"'),
        'Should have og:site_name',
      );
      assert.ok(
        html.includes('property="og:title"'),
        'Should have og:title',
      );
      assert.ok(
        html.includes('property="og:description"'),
        'Should have og:description',
      );
    });

    it('should escape HTML entities in parameters', async () => {
      const payload = '&lt;script&gt;alert(1)&lt;/script&gt;';
      const url = `https://${TEST_DOMAIN}${explorerPath}?filter=${encodeURIComponent(payload)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Already encoded entities should be double-escaped
      assert.ok(
        html.includes('&amp;lt;script&amp;gt;'),
        'HTML entities should be double-escaped to prevent decoding attacks',
      );
    });

    it('should handle Unicode XSS attempts', async () => {
      const unicodeXSS = '\u003Cscript\u003Ealert(1)\u003C/script\u003E';
      const url = `https://${TEST_DOMAIN}${explorerPath}?filter=${encodeURIComponent(unicodeXSS)}`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Unicode should be properly handled and escaped
      assert.ok(
        !html.includes('<script>alert(1)</script>'),
        'Unicode XSS should not execute',
      );
      assert.ok(
        html.includes('&lt;script&gt;') || html.includes('&amp;lt;'),
        'Unicode characters should be escaped',
      );
    });

    it('should maintain OpenGraph image and other meta tags', async () => {
      const url = `https://${TEST_DOMAIN}${explorerPath}?domain=test.com`;

      const response = await fetch(url);
      assert.strictEqual(response.status, 200, 'Should return 200 OK');

      const html = await response.text();

      // Check that all OpenGraph tags are present
      assert.ok(
        html.includes('property="og:site_name" content="RUM Explorer"'),
        'Should have og:site_name',
      );
      assert.ok(
        html.includes('property="og:image"'),
        'Should have og:image',
      );
      assert.ok(
        html.includes('property="og:image:width" content="500"'),
        'Should have og:image:width',
      );
      assert.ok(
        html.includes('property="og:image:height" content="348"'),
        'Should have og:image:height',
      );
      assert.ok(
        html.includes('property="og:image:type" content="image/jpeg"'),
        'Should have og:image:type',
      );
    });
  });

  // Keep the original simple test for backwards compatibility
  it('passes', async () => {
    assert.ok(true);
  });
});
