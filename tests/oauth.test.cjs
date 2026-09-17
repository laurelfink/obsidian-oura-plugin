const {test} = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const ts = require('typescript');
const {webcrypto} = require('node:crypto');

function fixture(handler = async () => tokenResponse()) {
  const requests = [];
  const module = {exports: {}};
  const source = ts.transpileModule(fs.readFileSync('src/oauth.ts', 'utf8'), {
    compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020},
  }).outputText;
  vm.runInNewContext(source, {
    module, exports: module.exports, URL, URLSearchParams, crypto: webcrypto,
    require: () => ({requestUrl: async options => { requests.push(options); return handler(options); }}),
  });
  const settings = {clientId: 'test-id', clientSecret: 'test-secret', redirectUri: 'obsidian://oura-oauth', oauthTokens: null};
  let saves = 0;
  const oauth = new module.exports.OuraOAuth(settings, async () => { saves++; });
  return {oauth, settings, requests, saves: () => saves};
}
function tokenResponse(access = 'new-access', refresh = 'new-refresh') {
  return {status: 200, json: {access_token: access, refresh_token: refresh, token_type: 'bearer', expires_in: 3600}};
}
function start(f) { return new URL(f.oauth.authorize()).searchParams.get('state'); }
function expired(f) { f.settings.oauthTokens = {accessToken: 'old', refreshToken: 'refresh', expiresAt: 0}; }

test('authorization requests daily scope; exchange persists tokens and binds redirect URI', async () => {
  const f = fixture();
  const url = new URL(f.oauth.authorize());
  assert.equal(url.origin, 'https://cloud.ouraring.com');
  assert.equal(url.searchParams.get('scope'), 'daily');
  assert.equal(url.searchParams.get('response_type'), 'code');
  await f.oauth.complete({code: 'code & value', state: url.searchParams.get('state'), scope: 'daily'});
  const body = new URLSearchParams(f.requests[0].body);
  assert.equal(body.get('code'), 'code & value');
  assert.equal(body.get('redirect_uri'), f.settings.redirectUri);
  assert.equal(body.get('client_secret'), 'test-secret');
  assert.equal(f.settings.oauthTokens.refreshToken, 'new-refresh');
  assert.equal(f.saves(), 1);
  await assert.rejects(f.oauth.complete({code: 'replay', state: url.searchParams.get('state')}), /expired/);
});

test('wrong state, denied consent, and missing daily scope never exchange tokens', async () => {
  const f = fixture();
  const state = start(f);
  await assert.rejects(f.oauth.complete({code: 'code', state: 'wrong'}), /did not match/);
  await assert.rejects(f.oauth.complete({error: 'access_denied', state}), /denied/);
  await assert.rejects(f.oauth.complete({code: 'code', state: start(f), scope: 'email'}), /Daily data/);
  assert.equal(f.requests.length, 0);
});

test('manual callback validates destination and completes authorization', async () => {
  const f = fixture();
  const state = start(f);
  await assert.rejects(f.oauth.completeUrl(`https://wrong.example/?code=code&state=${state}`), /does not match/);
  await f.oauth.completeUrl(`obsidian://oura-oauth?code=code&state=${state}`);
  assert.equal(f.requests.length, 1);
});

test('concurrent refreshes share one exchange and rotate the refresh token', async () => {
  const f = fixture(); expired(f);
  const result = await Promise.all([f.oauth.accessToken(), f.oauth.accessToken(), f.oauth.accessToken()]);
  assert.deepEqual(result, ['new-access', 'new-access', 'new-access']);
  assert.equal(f.requests.length, 1);
  assert.equal(new URLSearchParams(f.requests[0].body).get('refresh_token'), 'refresh');
  assert.equal(f.settings.oauthTokens.refreshToken, 'new-refresh');
  await f.oauth.accessToken();
  assert.equal(f.requests.length, 1);
});

test('401 refreshes and retries once with the replacement token', async () => {
  const f = fixture(async options => options.method === 'POST' ? tokenResponse() :
    {status: options.headers.Authorization === 'Bearer old' ? 401 : 200});
  f.settings.oauthTokens = {accessToken: 'old', refreshToken: 'refresh', expiresAt: Date.now() + 3600000};
  assert.equal((await f.oauth.request('https://api.ouraring.com/test')).status, 200);
  assert.equal(f.requests.length, 3);
});

test('repeated 401 stops after one retry; 403 does not refresh', async () => {
  for (const status of [401, 403]) {
    const f = fixture(async options => options.method === 'POST' ? tokenResponse() : {status});
    f.settings.oauthTokens = {accessToken: 'old', refreshToken: 'refresh', expiresAt: Date.now() + 3600000};
    await assert.rejects(f.oauth.request('https://api.ouraring.com/test'), /Reconnect/);
    assert.equal(f.requests.length, status === 401 ? 3 : 1);
  }
});

test('only invalid_grant clears refresh tokens; other token failures preserve them', async () => {
  for (const [status, error, clears] of [
    [400, 'invalid_grant', true], [401, 'invalid_grant', true],
    [400, 'invalid_request', false], [401, 'invalid_client', false],
    [400, undefined, false], [401, undefined, false],
    [429, 'invalid_grant', false], [500, 'server_error', false],
  ]) {
    const f = fixture(async () => ({status, json: {error}})); expired(f);
    const previous = f.settings.oauthTokens;
    await assert.rejects(f.oauth.accessToken());
    assert.equal(f.settings.oauthTokens, clears ? null : previous);
    assert.equal(f.saves(), clears ? 1 : 0);
  }
});

test('non-JSON refresh errors preserve tokens and return a friendly message', async () => {
  const f = fixture(async () => ({status: 400, get json() { throw new SyntaxError('Unexpected token'); }}));
  expired(f);
  const previous = f.settings.oauthTokens;
  await assert.rejects(f.oauth.accessToken(), /Check settings and reconnect/);
  assert.equal(f.settings.oauthTokens, previous);
});

test('malformed and unsupported configured redirects have actionable errors', async () => {
  for (const redirect of ['', 'not a URL', 'https://', 'http://example.com', 'obsidian://other']) {
    const f = fixture();
    f.settings.redirectUri = redirect;
    assert.throws(() => f.oauth.authorize(), /Enter a valid redirect URI/);
    await assert.rejects(f.oauth.completeUrl('https://example.com/?code=test'), /Enter a valid redirect URI/);
    assert.equal(f.requests.length, 0);
  }
});

test('malformed pasted callback has an actionable error', async () => {
  const f = fixture();
  await assert.rejects(f.oauth.completeUrl('not a URL'), /Paste the complete redirect URL/);
  assert.equal(f.requests.length, 0);
});

test('disconnect while exchanging cannot restore tokens', async () => {
  let resolve;
  const f = fixture(() => new Promise(done => { resolve = done; }));
  const pending = f.oauth.complete({code: 'code', state: start(f)});
  await f.oauth.disconnect();
  resolve(tokenResponse());
  await assert.rejects(pending, /connection changed/);
  assert.equal(f.settings.oauthTokens, null);
});

test('settings changes cancel sign-in and invalid token responses are not stored', async () => {
  const f = fixture(async () => ({status: 200, json: {access_token: 'incomplete'}}));
  const state = start(f);
  f.oauth.cancel();
  await assert.rejects(f.oauth.complete({code: 'code', state}), /expired/);
  await assert.rejects(f.oauth.complete({code: 'code', state: start(f)}), /invalid token/);
  assert.equal(f.settings.oauthTokens, null);
});

test('legacy token authenticates requests without attempting OAuth refresh', async () => {
  for (const status of [200, 401]) {
    const f = fixture(async () => ({status}));
    f.settings.personalAccessToken = 'legacy';
    if (status === 200) await f.oauth.request('https://api.ouraring.com/test');
    else await assert.rejects(f.oauth.request('https://api.ouraring.com/test'), /Reconnect/);
    assert.equal(f.requests.length, 1);
    assert.equal(f.requests[0].headers.Authorization, 'Bearer legacy');
    assert.equal(f.settings.personalAccessToken, 'legacy');
  }
});

test('OAuth takes precedence and never falls back to legacy after rejection', async () => {
  const f = fixture(async options => options.method === 'POST' ? tokenResponse() : {status: 401});
  f.settings.personalAccessToken = 'legacy';
  f.settings.oauthTokens = {accessToken: 'oauth', refreshToken: 'refresh', expiresAt: Date.now() + 3600000};
  await assert.rejects(f.oauth.request('https://api.ouraring.com/test'), /Reconnect/);
  assert.equal(f.requests.length, 3);
  assert.equal(f.requests[0].headers.Authorization, 'Bearer oauth');
  assert.equal(f.requests[2].headers.Authorization, 'Bearer new-access');
});

test('only successful OAuth exchange removes legacy token; disconnect removes all tokens', async () => {
  const f = fixture();
  f.settings.personalAccessToken = 'legacy';
  await assert.rejects(f.oauth.complete({error: 'access_denied', state: start(f)}), /denied/);
  assert.equal(f.settings.personalAccessToken, 'legacy');
  await f.oauth.complete({code: 'code', state: start(f)});
  assert.equal('personalAccessToken' in f.settings, false);
  const legacyOnly = fixture();
  legacyOnly.settings.personalAccessToken = 'legacy';
  await legacyOnly.oauth.disconnect();
  assert.equal('personalAccessToken' in legacyOnly.settings, false);
  await assert.rejects(legacyOnly.oauth.request('https://api.ouraring.com/test'), /Connect/);
});

test('starting or cancelling sign-in during refresh preserves and saves rotated tokens', async () => {
  for (const action of ['authorize', 'cancel', 'edit']) {
    let resolve;
    const f = fixture(() => new Promise(done => { resolve = done; }));
    expired(f);
    const refreshing = f.oauth.accessToken();
    if (action === 'edit') { f.oauth.cancel(); f.settings.clientSecret = 'edited'; }
    else f.oauth[action]();
    resolve(tokenResponse());
    assert.equal(await refreshing, 'new-access');
    assert.equal(f.settings.oauthTokens.refreshToken, 'new-refresh');
    assert.equal(f.saves(), 1);
  }
});

test('disconnect during refresh discards rotated tokens and keeps the connection cleared', async () => {
  let resolve;
  const f = fixture(() => new Promise(done => { resolve = done; }));
  expired(f);
  const refreshing = f.oauth.accessToken();
  await f.oauth.disconnect();
  resolve(tokenResponse());
  await assert.rejects(refreshing, /connection changed/);
  assert.equal(f.settings.oauthTokens, null);
});

test('new authorization waits for refresh and then replaces the connection', async () => {
  let resolve;
  const f = fixture(options => new URLSearchParams(options.body).get('grant_type') === 'refresh_token'
    ? new Promise(done => { resolve = done; }) : Promise.resolve(tokenResponse('connected-access', 'connected-refresh')));
  expired(f);
  const refreshing = f.oauth.accessToken();
  const completing = f.oauth.complete({code: 'code', state: start(f)});
  assert.equal(f.requests.length, 1);
  resolve(tokenResponse());
  await Promise.all([refreshing, completing]);
  assert.equal(f.settings.oauthTokens.refreshToken, 'connected-refresh');
  assert.equal(f.saves(), 2);
});

test('cancelling an in-flight code exchange still prevents saving its tokens', async () => {
  let resolve;
  const f = fixture(() => new Promise(done => { resolve = done; }));
  const completing = f.oauth.complete({code: 'code', state: start(f)});
  f.oauth.cancel();
  resolve(tokenResponse());
  await assert.rejects(completing, /connection changed/);
  assert.equal(f.settings.oauthTokens, null);
});
