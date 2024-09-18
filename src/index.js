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

/**
 * @typedef {{
*   IMAGE_BUCKET: R2Bucket;
* } & Record<string, string>} Env
*/

/**
* Base64 string to ArrayBuffer
* @param {string} base64
* @returns {ArrayBuffer}
*/
function base64ToArrayBuffer(base64) {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
* Get PSI API URL
* @param {URL} url
* @param {Env} env
* @returns {string}
*/
function getPsiUrl(url, env) {
  return `https://pagespeedonline.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url.toString())}&key=${env.PSI_KEY}&strategy=desktop&category=performance`;
}

/**
 * Validates a domainkey against the RUM Bundler API
 * @param {string} domain the domain, e.g. "www.example.com"
 * @param {string} key the domainkey to validate
 * @returns {Promise<boolean>} true if the domainkey is valid, exception otherwise
 */
async function isDomainkeyValid(domain, key) {
  if (!domain || !key) {
    throw new Error('missing domain or key');
  }
  try {
    const beurl = new URL(`https://rum.fastly-aem.page/domains/${domain}`);
    beurl.searchParams.set('domainkey', key);

    const beresp = await fetch(beurl, {
      cf: {
        // keep the auth in cache for 10 minutes
        cacheTtl: 600,
        cacheEverything: true,
      },
    });
    if (!beresp.ok) {
      throw new Error('unable to fetch from RUM Bundler API: ' + beresp.statusText);
    }
    return true;
  } catch (e) {
    throw new Error('other error validating domain key: ' + e.message);
  }
}

async function handleCorsRoute(req, env) {
  const url = new URL(req.url);
  const params = new URLSearchParams(url.search);

  const beurl = new URL(params.get('url'));
  const domainkey = params.get('domainkey');

  try {
    await isDomainkeyValid(beurl.hostname, domainkey);
    const beresp = await fetch(beurl, {
      cf: {
        cacheTtl: 3600,
        cacheEverything: true,
      },
    });
    // if not ok, or response is neither HTML or JSON, return 404
    if (!beresp.ok
      || !beresp.headers.get('content-type').includes('html')
      || !beresp.headers.get('content-type').includes('json')) {
      return new Response('', {
        status: 404,
        headers: {
          'x-error': 'not found: ' + beresp.statusText,
        },
      });
    }
    const headers = new Headers(beresp.headers);
    headers.set('access-control-allow-origin', '*');
    headers.set('access-control-allow-credentials', 'true');
    headers.set('access-control-allow-headers', 'Content-Type');
    headers.set('access-control-allow-methods', 'GET, POST, OPTIONS');
    headers.set('access-control-max-age', '86400');

    // allow CORS
    return new Response(beresp.body, {
      status: 200,
      headers
    });
  } catch (e) {
    // return 503
    return new Response('', {
      status: 503,
      headers: {
        'x-error': e.message,
      },
    });
  }
}

/**
* Check if image exists and is not pending/failed
* @param {string} key
* @param {Env} env
* @returns {Promise<boolean>}
*/
async function isImageReady(key, env) {
  const resp = await env.IMAGE_BUCKET.head(key);
  if (!resp) {
    return false;
  }
  if (resp.customMetadata.state === 'pending'
   || resp.customMetadata.state === 'failed') {
    return false;
  }
  return true;
}

/**
* Check if image exists, in any state: loaded, pending, failed
* @param {string} key
* @param {Env} env
* @returns {Promise<boolean>}
*/
async function doesImageExist(key, env) {
  const resp = await env.IMAGE_BUCKET.head(key);
  return !!resp;
}

/**
* @param {Env} env
* @param {string} key
* @param {'loaded'|'pending'|'failed'} state
* @param {string|ArrayBuffer} [data='']
* @param {string} [contentType]
* @returns {Promise<void>}
*/
async function storeImage(env, key, state, data = '', contentType) {
  await env.IMAGE_BUCKET.put(key, data, {
    customMetadata: {
      state,
    },
    ...(contentType
      ? { httpMetadata: { contentType } }
      : {}),
  });
}

/**
* Fetch screenshot using PSI service
*
* @param {URL} url
* @param {Env} env
* @returns {Promise<{data: ArrayBuffer; type: string;}>}
*/
async function fetchScreenshot(url, env) {
  const psiUrl = getPsiUrl(url, env);
  console.debug('psiUrl: ', psiUrl);
  const psiResp = await fetch(psiUrl);
  if (!psiResp.ok) {
    console.error('psi failed: ', await psiResp.text());
    throw new Error(`psi failed (${psiResp.status})`);
  }

  const {
    lighthouseResult: {
      audits: {
        'final-screenshot': {
          details: { data },
        },
      },
    },
  } = await psiResp.json();
  const [prefix, b64str] = data.split(',');
  const [type] = prefix.split(':')[1].split(';');
  const buf = base64ToArrayBuffer(b64str);
  console.debug('got psi screenshot buffer');

  return {
    data: buf,
    type,
  };
}

/**
* Initiate processing image from PSI
* Bails if the image is pending
*
* @param {string} key storage key
* @param {URL} purl explorer url
* @param {Env} env
* @returns {Promise<Response>}
*/
async function initImage(key, purl, env) {
  if (await doesImageExist(key, env)) {
    return;
  }

  // immediately store pending meta
  await storeImage(env, key, 'pending');

  const url = new URL(purl);
  url.hostname = 'main--helix-website--adobe.aem.live';
  url.pathname = '/tools/rum/explorer.html';

  try {
    const { data, type } = await fetchScreenshot(url, env);
    // store in r2, remove "pending" flag
    await storeImage(env, key, 'loaded', data, type);
  } catch (e) {
    console.error('failed to create image buffer: ', e);
    // store "failed" in r2, indicate we should perm redirect?
    await storeImage(env, key, 'failed', e.message, 'plain/text');
  }
}

/**
* @param {Request} req
* @param {URL} url
* @returns
*/
async function fetchOGImage(req, url) {
  /** @type {string|undefined} */
  let ogUrl;
  const resp = await fetch(url, {
    headers: {
      'user-agent': req.headers.get('user-agent'),
    },
  });
  const rewriter = new HTMLRewriter();
  const rewritten = rewriter
    .on('meta[property="og:image"]', {
      element(element) {
        ogUrl = element.getAttribute('content');
        throw Error('done');
      },
    })
    .transform(resp);

  try {
    await rewritten.text();
    return new Response('', { status: 404 });
  } catch (e) {
    if (e.message === 'done') {
      if (!ogUrl) {
        return new Response('', { status: 404 });
      }
      console.log('proxying og:image: ', ogUrl);
      return new Response('', {
        status: 301,
        headers: {
          location: ogUrl,
          'cache-control': 'public, max-age=7200',
        },
      });
    }
    return new Response('', {
      status: 400,
      headers: {
        'x-error': e.message,
      },
    });
  }
}

/**
* @param {Request} req
* @param {string} purl
* @param {'screenshot'|'ogimage'|string|undefined} mode
* @param {Env} env
* @returns {Promise<Response>}
*/
async function proxyImage(req, purl, mode, env) {
  /** @type {URL} */
  let url;
  try {
    url = new URL(purl);
    if (url.protocol === 'android-app:') {
      const aurl = new URL('https://play.google.com/store/apps/details');
      aurl.searchParams.set('id', url.hostname);
      url = aurl;
    }
  } catch {
    return new Response('', {
      status: 400,
      headers: {
        'x-error': 'invalid url',
      },
    });
  }

  // console.log('proxying image: ', purl);
  if (mode === 'screenshot') {
    try {
      const { data, type } = await fetchScreenshot(url, env);
      return new Response(data, {
        status: 200,
        headers: {
          'content-type': type,
          'cache-control': 'public, max-age=31536000',
        },
      });
    } catch (e) {
      console.error('failed to fetch screenshot: ', e);
      return new Response('', {
        status: 500,
        headers: {
          'x-error': 'failed to take screenshot',
        },
      });
    }
  } else {
    return fetchOGImage(req, url);
  }
}

/**
* Handle /tools/rum/_ogimage route
* @param {Request} req
* @param {Env} env
* @param {ExecutionContext} ctx
* @returns {Promise<Response>}
*/
async function handleImageRoute(req, env, ctx) {
  const url = new URL(req.url);
  const params = new URLSearchParams(url.search);

  const domain = params.get('domain');
  const proxyUrl = params.get('proxyurl');
  if (!domain && proxyUrl) {
    const mode = params.get('mode');
    return proxyImage(req, proxyUrl, mode, env);
  }

  const view = params.get('view');
  if (!domain || !view) {
    return new Response('', {
      status: 400,
      headers: {
        'x-error': 'missing domain or view',
      },
    });
  }

  params.sort();
  const key = `images/${domain}/${view}/${params.toString()}`; // storage key

  // if image is ready, respond with the image
  if (await isImageReady(key, env)) {
    const imResp = await env.IMAGE_BUCKET.get(key);
    const buf = await imResp.arrayBuffer();
    return new Response(buf, {
      status: 200,
      headers: {
        'cache-control': 'public, max-age=31536000',
        'content-type': imResp.httpMetadata.contentType,
      },
    });
  }

  // otherwise, initiate PSI & respond with 302 to default temp image
  ctx.waitUntil(initImage(key, url, env));
  return new Response('', {
    status: 302,
    headers: {
      location: 'https://www.aem.live/default-social.png?width=1200&#x26;format=pjpg&#x26;optimize=medium',
    },
  });
}

/**
* Handle request
* @param {Request} request
* @param {Env} env
* @param {ExecutionContext} ctx
* @returns {Promise<Response>}
*/
const handleRequest = async (request, env, ctx) => {
  const url = new URL(request.url);

  if (url.pathname.startsWith('/tools/rum/_ogimage')) {
    return handleImageRoute(request, env, ctx);
  }

  if (url.pathname.startsWith('/tools/rum/_cors')) {
    return handleCorsRoute(request, env, ctx);
  }

  url.hostname = 'main--helix-website--adobe.aem.live';
  const req = new Request(url, request);
  const resp = await fetch(req, {
    cf: {
      // cf doesn't cache html by default: need to override the default behavior
      cacheEverything: true,
    },
  });

  if (!resp.ok) {
    return resp;
  }

  if (url.pathname === '/tools/rum/explorer.html') {
    const text = await resp.text();
    const params = new URLSearchParams(url.search);
    params.sort();
    const domain = params.get('domain') || '';
    const view = (params.get('view') || '').toLowerCase();
    const viewly = view === 'day'
      ? 'Daily '
      : view
        ? `${view[0].toUpperCase()}${view.substring(1)}ly `
        : '';
    const filter = params.get('filter');
    const checkpoints = params.getAll('checkpoint').join(',');
    const detailArr = [
      filter || undefined,
      checkpoints || undefined,
    ].filter((d) => d != null);
    const detail = detailArr.length ? ` (${detailArr.join(', ')})` : '';

    const og = `\
   <meta property="og:site_name" content="RUM Explorer" />
       <meta property="og:title" content="RUM Data for ${domain}" />
       <meta property="og:description" content="${viewly}RUM data for ${domain}${detail}" />
       <meta property="og:image" content="https://www.aem.live/tools/rum/_ogimage?${params.toString()}" />
       <meta property="og:image:width" content="500" />
       <meta property="og:image:height" content="348" />
       <meta property="og:image:type" content="image/jpeg" />
   </head>
   `;
    const splits = text.split('</head>');
    const body = splits.join(og);
    return new Response(body, resp);
  }

  return resp;
};

export default {
  fetch: handleRequest,
};
