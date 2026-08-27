import { Buffer } from 'node:buffer';
import { nvidiaNrasVerifier } from '../../src/utils/nvidia';

describe('NVIDIA NRAS verification', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('accepts a true overall NRAS result', async () => {
    mockNrasOverallResult(true);

    await expect(nvidiaNrasVerifier('{}')).resolves.toBeUndefined();
  });

  test('rejects a false overall NRAS result', async () => {
    mockNrasOverallResult(false);

    await expect(nvidiaNrasVerifier('{}')).rejects.toMatchObject({
      failure: {
        phase: 'gpu',
        code: 'gpu.attestation_rejected',
        details: { source: 'nras' },
      },
    });
  });

  test.each(['PASS', 'FAIL'])(
    'rejects the undocumented string result %s',
    async (result) => {
      mockNrasOverallResult(result);

      await expect(nvidiaNrasVerifier('{}')).rejects.toMatchObject({
        failure: {
          phase: 'gpu',
          code: 'gpu.nras_response_invalid',
          details: { reason: 'invalid_verdict_type' },
        },
      });
    },
  );

  test.each([null, [], true, 'claims'])(
    'rejects a non-object JWT payload (%p) as an invalid NRAS response',
    async (payload) => {
      mockNrasJwtPayload(payload);

      await expect(nvidiaNrasVerifier('{}')).rejects.toMatchObject({
        failure: {
          phase: 'gpu',
          code: 'gpu.nras_response_invalid',
          details: { reason: 'invalid_jwt' },
        },
      });
    },
  );
});

function mockNrasOverallResult(result: boolean | string): void {
  mockNrasJwtPayload({ 'x-nvidia-overall-att-result': result });
}

function mockNrasJwtPayload(payload: unknown): void {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString(
    'base64url',
  );
  const encodedPayload = Buffer.from(JSON.stringify(payload)).toString(
    'base64url',
  );
  const jwt = `${header}.${encodedPayload}.signature`;

  jest.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => [['JWT', jwt]],
  } as Response);
}
