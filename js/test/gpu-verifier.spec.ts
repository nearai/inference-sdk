import { generateKeyPairSync, sign } from 'node:crypto';
import { createGpuEvidenceVerifier } from '../src';

const nrasUrl = '/api/proxy/nras/v3/attest/gpu';
const jwksUrl = '/api/proxy/nras/.well-known/jwks.json';
const nonce = 'ab'.repeat(32);
const payload = JSON.stringify({ nonce });
const first = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
const second = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
const keys = (pair = first, kid = 'first') => ({
  keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid }],
});
let jwt: string;
let jwks: ReturnType<typeof keys>;

function token(
  overrides: Record<string, unknown> = {},
  pair = first,
  kid = 'first',
) {
  const now = Math.floor(Date.now() / 1000);
  const header = Buffer.from(JSON.stringify({ alg: 'ES384', kid })).toString(
    'base64url',
  );
  const claims = Buffer.from(
    JSON.stringify({
      iss: 'https://nras.attestation.nvidia.com',
      exp: now + 3600,
      nbf: now - 5,
      iat: now - 5,
      eat_nonce: nonce,
      'x-nvidia-overall-att-result': true,
      ...overrides,
    }),
  ).toString('base64url');
  const text = `${header}.${claims}`;
  const signature = sign('sha384', Buffer.from(text), {
    key: pair.privateKey,
    dsaEncoding: 'ieee-p1363',
  });
  return `${text}.${signature.toString('base64url')}`;
}

beforeEach(() => {
  jest.useFakeTimers({ now: 1_800_000_000_000 });
  jwks = keys();
  jwt = token();
  jest
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (url) =>
      Response.json(String(url) === nrasUrl ? [['JWT', jwt]] : jwks),
    );
});
afterEach(() => {
  jest.restoreAllMocks();
  jest.useRealTimers();
});

const verifier = (options = {}) =>
  createGpuEvidenceVerifier({ nrasUrl, jwksUrl, ...options });
const jwksCalls = () =>
  jest.mocked(fetch).mock.calls.filter(([url]) => url === jwksUrl);

test.each(['iat', 'nbf'])('defaults to strict %s checks', async (claim) => {
  jwt = token({ [claim]: Date.now() / 1000 + 1 });
  await expect(verifier()(payload)).rejects.toMatchObject({
    failure: {
      code: 'gpu.jwt_verification_failed',
      details: { reason: 'not_yet_valid' },
    },
  });
});

test('allows configured future iat/nbf skew at its boundary', async () => {
  jwt = token({ iat: Date.now() / 1000 + 30, nbf: Date.now() / 1000 + 30 });
  await expect(
    verifier({ clockToleranceSeconds: 30 })(payload),
  ).resolves.toBeUndefined();
});

test.each(['iat', 'nbf'])(
  'rejects %s beyond the configured tolerance',
  async (claim) => {
    jwt = token({ [claim]: Date.now() / 1000 + 31 });
    await expect(
      verifier({ clockToleranceSeconds: 30 })(payload),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.jwt_verification_failed',
        details: { reason: 'not_yet_valid' },
      },
    });
  },
);

test.each([0, -1])(
  'never extends expiry with tolerance (offset %s)',
  async (offset) => {
    jwt = token({
      exp: Date.now() / 1000 + offset,
      iat: Date.now() / 1000 + 2,
      nbf: Date.now() / 1000 + 2,
    });
    await expect(
      verifier({ clockToleranceSeconds: 30 })(payload),
    ).rejects.toMatchObject({
      failure: {
        code: 'gpu.jwt_verification_failed',
        details: { reason: 'expired' },
      },
    });
  },
);

test('does not relax signature verification when tolerance is enabled', async () => {
  jwt = token({ iat: Date.now() / 1000 + 2, nbf: Date.now() / 1000 + 2 });
  const parts = jwt.split('.');
  parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
  jwt = parts.join('.');
  await expect(
    verifier({ clockToleranceSeconds: 30 })(payload),
  ).rejects.toMatchObject({
    failure: {
      code: 'gpu.jwt_verification_failed',
      details: { reason: 'invalid_signature' },
    },
  });
});

test.each([
  [{ eat_nonce: 'cd'.repeat(32) }, 'gpu.jwt_verification_failed'],
  [{ 'x-nvidia-overall-att-result': false }, 'gpu.attestation_rejected'],
])(
  'keeps nonce and verdict checks with tolerance enabled (%p)',
  async (claims, code) => {
    jwt = token(claims);
    await expect(
      verifier({ clockToleranceSeconds: 30 })(payload),
    ).rejects.toMatchObject({
      failure: { code },
    });
  },
);

test('keeps caching disabled by default', async () => {
  const verify = verifier();
  await verify(payload);
  await verify(payload);
  expect(jwksCalls()).toHaveLength(2);
});

test('shares enabled JWKS cache and in-flight requests across replicas', async () => {
  const verify = verifier({ jwksCacheTtlMs: 1000 });
  await Promise.all([verify(payload), verify(payload), verify(payload)]);
  await verify(payload);
  expect(jwksCalls()).toHaveLength(1);
  expect(
    jest.mocked(fetch).mock.calls.filter(([url]) => url === nrasUrl),
  ).toHaveLength(4);
});

test('reloads keys when the cache expires', async () => {
  const verify = verifier({ jwksCacheTtlMs: 1000 });
  await verify(payload);
  jest.setSystemTime(Date.now() + 1000);
  await verify(payload);
  expect(jwksCalls()).toHaveLength(2);
});

test('refreshes a missing rotated key once across concurrent replicas', async () => {
  const verify = verifier({ jwksCacheTtlMs: 3_600_000 });
  await verify(payload);
  jwt = token({}, second, 'second');
  jwks = keys(second, 'second');
  await Promise.all([verify(payload), verify(payload)]);
  await verify(payload);
  expect(jwksCalls()).toHaveLength(2);
});

test('rejects a key still missing after one refresh', async () => {
  const verify = verifier({ jwksCacheTtlMs: 1000 });
  await verify(payload);
  jwt = token({}, second, 'second');
  await expect(verify(payload)).rejects.toMatchObject({
    failure: {
      code: 'gpu.jwt_verification_failed',
      details: { reason: 'key_not_found' },
    },
  });
  expect(jwksCalls()).toHaveLength(2);
});

test('does not cache failed JWKS fetches', async () => {
  const verify = verifier({ jwksCacheTtlMs: 1000 });
  jest
    .mocked(fetch)
    .mockImplementationOnce(async () => Response.json([['JWT', jwt]]))
    .mockRejectedValueOnce(new Error('offline'));
  await expect(verify(payload)).rejects.toMatchObject({
    failure: { code: 'gpu.jwks_request_failed' },
  });
  await expect(verify(payload)).resolves.toBeUndefined();
  expect(jwksCalls()).toHaveLength(2);
});

test('preserves a JWKS outage during rotation and retries on the next call', async () => {
  const verify = verifier({ jwksCacheTtlMs: 1000 });
  await verify(payload);
  jwt = token({}, second, 'second');
  jwks = keys(second, 'second');
  jest
    .mocked(fetch)
    .mockImplementationOnce(async () => Response.json([['JWT', jwt]]))
    .mockRejectedValueOnce(new Error('offline'));
  await expect(verify(payload)).rejects.toMatchObject({
    failure: { code: 'gpu.jwks_request_failed' },
  });
  await expect(verify(payload)).resolves.toBeUndefined();
  expect(jwksCalls()).toHaveLength(3);
});

test('isolates caches between verifier instances and trusted JWKS URLs', async () => {
  await verifier({ jwksCacheTtlMs: 1000 })(payload);
  jwks = keys(second, 'second');
  jwt = token({}, second, 'second');
  await verifier({
    jwksUrl: '/another-trusted-proxy/jwks.json',
    jwksCacheTtlMs: 1000,
  })(payload);
  expect(fetch).toHaveBeenCalledWith('/another-trusted-proxy/jwks.json');
});

test.each([-1, NaN, Infinity])('rejects invalid option %s', (value) => {
  expect(() => verifier({ clockToleranceSeconds: value })).toThrow(RangeError);
  expect(() => verifier({ jwksCacheTtlMs: value })).toThrow(RangeError);
});
