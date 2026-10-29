import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const value = (name) => {
  const result = process.env[`AGENT_VAULT_TEST_${name}`];
  assert.ok(result, `missing test ${name}`);
  return result;
};
const baseURL = value('URL');
const token = (await readFile(value('TOKEN_FILE'), 'utf8')).trim();
const user = value('USER_ID');
const connection = value('CONNECTION_ID');
const path = `/v1/managed-users/${encodeURIComponent(user)}`;

async function request(method, route, body, extraHeaders = {}) {
  const response = await fetch(`${baseURL}${route}`, {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
      ...extraHeaders,
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
  const text = await response.text();
  const json = response.headers.get('content-type')?.includes('application/json');
  return { status: response.status, body: text ? (json ? JSON.parse(text) : text) : undefined };
}

const callback = {
  state: value('STATE'),
  code: value('CODE'),
  iss: value('ISSUER'),
  user_id: user,
};
assert.equal(
  (await request('POST', '/v1/oauth/complete', {
    ...callback,
    user_id: value('SUBJECT'),
  })).status,
  403,
);
const completed = await request('POST', '/v1/oauth/complete', callback);
assert.equal(completed.status, 200);
assert.equal(completed.body.connection_id, connection);
assert.equal(completed.body.status, 'connected');
assert.equal(completed.body.key, undefined);
assert.equal(completed.body.vault, undefined);

const owned = await request('GET', `${path}/connections/${connection}`);
assert.equal(owned.status, 200);
assert.equal(owned.body.owner.id, user);
assert.equal(owned.body.status, 'ready');
assert.match(owned.body.revision, /^"[0-9a-f]{64}"$/);
for (const name of ['services', 'credentials', 'grants']) {
  assert.ok(Array.isArray(owned.body[name]), `${name} must be an array`);
}
const vault = encodeURIComponent(value('VAULT'));
const grantRoute = `${path}/connections/${connection}/grants/${vault}`;
const grant = await request('PUT', grantRoute, {
  services: owned.body.services.map((service) => service.name),
}, { 'If-None-Match': '*' });
assert.equal(grant.status, 200);
const access = await request('GET', `${path}/vaults/${vault}/access`);
assert.equal(access.status, 200);
assert.ok(Array.isArray(access.body.grants));
assert.equal(access.body.grants[0].connection_id, connection);
assert.match(access.body.grants[0].services[0].auth.token, /^BIND_/);
assert.equal((await request('DELETE', grantRoute)).status, 204);
assert.equal((await request('GET', `${path}/connections/${connection}`)).body.status, 'ready');
assert.ok(Array.isArray((await request('GET', `${path}/oauth-apps`)).body.items));
assert.equal((await request('GET', '/v1/vaults/group-one/mcp-oauth')).status, 404);
console.log('Real HTTP managed gateway callback/grant/access contract passed.');
