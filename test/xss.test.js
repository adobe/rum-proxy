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
import { readFileSync } from 'fs';

describe('XSS Prevention Tests', () => {
  describe('escapeHtml function', () => {
    let escapeHtml;

    before(() => {
      // Extract the escapeHtml function from index.js for testing
      const indexContent = readFileSync('./src/index.js', 'utf8');
      const escapeHtmlMatch = indexContent.match(/function escapeHtml\(text\) \{[\s\S]*?return String\(text\)\.replace[\s\S]*?\}/);
      if (escapeHtmlMatch) {
        // eslint-disable-next-line no-eval
        eval(`escapeHtml = ${escapeHtmlMatch[0]}`);
      }
    });

    it('should escape HTML special characters', () => {
      assert.strictEqual(escapeHtml('<script>alert(1)</script>'), '&lt;script&gt;alert(1)&lt;/script&gt;');
      assert.strictEqual(escapeHtml('"><img src=x onerror=alert(1)>'), '&quot;&gt;&lt;img src=x onerror=alert(1)&gt;');
      assert.strictEqual(escapeHtml("' onmouseover='alert(1)'"), '&#039; onmouseover=&#039;alert(1)&#039;');
    });

    it('should escape all dangerous characters', () => {
      assert.strictEqual(escapeHtml('<'), '&lt;');
      assert.strictEqual(escapeHtml('>'), '&gt;');
      assert.strictEqual(escapeHtml('"'), '&quot;');
      assert.strictEqual(escapeHtml("'"), '&#039;');
      assert.strictEqual(escapeHtml('&'), '&amp;');
    });

    it('should handle combined XSS payloads', () => {
      assert.strictEqual(
        escapeHtml('"><script>alert(document.cookie)</script>'),
        '&quot;&gt;&lt;script&gt;alert(document.cookie)&lt;/script&gt;',
      );
      assert.strictEqual(
        escapeHtml("'><img src='x' onerror='alert(1)'>"),
        '&#039;&gt;&lt;img src=&#039;x&#039; onerror=&#039;alert(1)&#039;&gt;',
      );
    });

    it('should handle empty and null inputs', () => {
      assert.strictEqual(escapeHtml(''), '');
      assert.strictEqual(escapeHtml(null), '');
      assert.strictEqual(escapeHtml(undefined), '');
    });

    it('should preserve safe text', () => {
      assert.strictEqual(escapeHtml('Hello World'), 'Hello World');
      assert.strictEqual(escapeHtml('user@example.com'), 'user@example.com');
      assert.strictEqual(escapeHtml('Price: $50.00'), 'Price: $50.00');
    });

    it('should handle unicode and encoded payloads', () => {
      assert.strictEqual(escapeHtml('&lt;script&gt;'), '&amp;lt;script&amp;gt;');
      assert.strictEqual(escapeHtml('javascript:alert(1)'), 'javascript:alert(1)');
      assert.strictEqual(escapeHtml('\u003Cscript\u003E'), '&lt;script&gt;');
    });

    it('should handle HTML entities in input', () => {
      assert.strictEqual(escapeHtml('&nbsp;&copy;&reg;'), '&amp;nbsp;&amp;copy;&amp;reg;');
      assert.strictEqual(escapeHtml('&#60;&#62;'), '&amp;#60;&amp;#62;');
    });

    it('should handle very long strings', () => {
      const longString = '<script>' + 'a'.repeat(10000) + '</script>';
      const expected = '&lt;script&gt;' + 'a'.repeat(10000) + '&lt;/script&gt;';
      assert.strictEqual(escapeHtml(longString), expected);
    });
  });

  describe('Integration tests for Open Graph meta tags', () => {
    it('should prevent XSS in filter parameter', () => {
      // This test would require actually running the worker
      // For now, we verify that the escapeHtml function is called on filter
      const indexContent = readFileSync('./src/index.js', 'utf8');
      assert.ok(indexContent.includes('const filter = escapeHtml(filterRaw);'));
    });

    it('should prevent XSS in domain parameter', () => {
      const indexContent = readFileSync('./src/index.js', 'utf8');
      assert.ok(indexContent.includes('const domain = escapeHtml(domainRaw);'));
    });

    it('should prevent XSS in checkpoint parameter', () => {
      const indexContent = readFileSync('./src/index.js', 'utf8');
      assert.ok(indexContent.includes('const checkpoints = escapeHtml(checkpointsRaw);'));
    });

    it('should prevent XSS in view parameter', () => {
      const indexContent = readFileSync('./src/index.js', 'utf8');
      assert.ok(indexContent.includes('const viewly = escapeHtml(viewlyRaw);'));
    });
  });
});