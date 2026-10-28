import { Buffer } from 'node:buffer';
import {
  IntelCollateralCache,
  type IntelMaterial,
  materialExpiry,
} from '../src/utils/intel-collateral-cache';
import { createDeferred } from './fixtures';
import { collateralResponse, intelFixtureTime } from './intel-fixtures';

function material(expiresAt = 200, size = 1): IntelMaterial {
  return { body: Buffer.from('x'), issuerChain: '', expiresAt, size };
}

describe('Intel material retention boundaries', () => {
  beforeEach(() => jest.spyOn(Date, 'now').mockReturnValue(100));
  afterEach(() => jest.restoreAllMocks());

  test('rechecks expiry after awaiting an in-flight download', async () => {
    const pending = createDeferred<IntelMaterial>();
    const refreshed = material(300);
    const load = jest
      .fn()
      .mockImplementationOnce(() => pending.promise)
      .mockResolvedValue(refreshed);
    const cache = new IntelCollateralCache(globalThis.fetch);
    const first = cache.get('key', load);
    const waiter = cache.get('key', load);
    jest.mocked(Date.now).mockReturnValue(201);
    pending.resolve(material(200));
    await first;
    expect(await waiter).toBe(refreshed);
    expect(load).toHaveBeenCalledTimes(2);
  });

  test('bounds completed entries and evicts the least recently used material', async () => {
    const cache = new IntelCollateralCache(globalThis.fetch);
    const load = jest.fn(async () => material());
    for (let i = 0; i < 64; i++) await cache.get(String(i), load);
    await cache.get('0', load);
    await cache.get('64', load);
    await cache.get('0', load);
    expect(load).toHaveBeenCalledTimes(65);
    await cache.get('1', load);
    expect(load).toHaveBeenCalledTimes(66);
  });

  test('bounds retained bytes and does not retain oversized responses', async () => {
    const cache = new IntelCollateralCache(globalThis.fetch);
    const load = jest.fn(async () => material(200, 5 * 1024 * 1024));
    await cache.get('first', load);
    await cache.get('second', load);
    await cache.get('first', load);
    expect(load).toHaveBeenCalledTimes(3);
    const oversized = jest.fn(async () => material(200, 8 * 1024 * 1024 + 1));
    await cache.get('large', oversized);
    await cache.get('large', oversized);
    expect(oversized).toHaveBeenCalledTimes(2);
  });

  test('bounds pending entries without breaking consumers already waiting', async () => {
    const cache = new IntelCollateralCache(globalThis.fetch);
    const pending = createDeferred<IntelMaterial>();
    const load = jest.fn(() => pending.promise);
    const requests = Array.from({ length: 64 }, (_, index) =>
      cache.get(String(index), load),
    );
    requests.push(cache.get('0', load));
    const bypass = jest.fn(async () => material());
    await cache.get('overflow', bypass);
    await cache.get('overflow', bypass);
    expect(bypass).toHaveBeenCalledTimes(2);
    expect(load).toHaveBeenCalledTimes(64);
    pending.resolve(material());
    expect(await Promise.all(requests)).toHaveLength(65);
  });

  test('shares failures only while pending and permits a later retry', async () => {
    const cache = new IntelCollateralCache(globalThis.fetch);
    const pending = createDeferred<IntelMaterial>();
    const load = jest
      .fn()
      .mockImplementationOnce(() => pending.promise)
      .mockResolvedValue(material());
    const first = cache.get('key', load);
    const second = cache.get('key', load);
    const failure = new Error('Temporary outage');
    const results = Promise.allSettled([first, second]);
    pending.reject(failure);
    expect(await results).toEqual([
      { status: 'rejected', reason: failure },
      { status: 'rejected', reason: failure },
    ]);
    await expect(cache.get('key', load)).resolves.toEqual(material());
    expect(load).toHaveBeenCalledTimes(2);
  });

  test.each(['max-age=0', 'max-age=invalid', 'max-age="10'])(
    'does not retain %s responses',
    async (control) => {
      jest.mocked(Date.now).mockReturnValue(intelFixtureTime);
      const response = collateralResponse('/tdx/certification/v4/tcb');
      response.headers.set('cache-control', control);
      const expiresAt = materialExpiry(
        'tcb',
        Buffer.from(await response.arrayBuffer()),
        decodeURIComponent(response.headers.get('TCB-Info-Issuer-Chain') ?? ''),
        response.headers,
        intelFixtureTime,
      );
      expect(expiresAt).toBeLessThanOrEqual(intelFixtureTime);
    },
  );
});
