import { nvidiaNrasVerifier } from '../../src';

describe('nvidiaNrasVerifier', () => {
  afterEach(() => {
    jest.restoreAllMocks();
  });

  test('accepts a true overall NRAS result', async () => {
    mockNrasOverallResult(true);

    await expect(nvidiaNrasVerifier.verify('{}')).resolves.toBeUndefined();
  });

  test('rejects a false overall NRAS result', async () => {
    mockNrasOverallResult(false);

    await expect(nvidiaNrasVerifier.verify('{}')).rejects.toThrow(
      'NVIDIA NRAS reported a failed overall attestation result',
    );
  });

  test.each(['PASS', 'FAIL'])(
    'rejects the undocumented string result %s',
    async (result) => {
      mockNrasOverallResult(result);

      await expect(nvidiaNrasVerifier.verify('{}')).rejects.toThrow(
        'NVIDIA NRAS overall attestation result must be a boolean',
      );
    },
  );
});

function mockNrasOverallResult(result: boolean | string): void {
  const header = Buffer.from(JSON.stringify({ alg: 'none' })).toString(
    'base64url',
  );
  const payload = Buffer.from(
    JSON.stringify({ 'x-nvidia-overall-att-result': result }),
  ).toString('base64url');
  const jwt = `${header}.${payload}.signature`;

  jest.spyOn(globalThis, 'fetch').mockResolvedValue({
    ok: true,
    status: 200,
    json: async () => [['JWT', jwt]],
  } as Response);
}
