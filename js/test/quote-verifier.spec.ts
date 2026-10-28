import { Buffer } from 'node:buffer';
import { Quote, verify } from '@phala/dcap-qvl';
import { getIntelCollateral } from '../src/utils/intel-collateral';
import { createTdxQuoteVerifier } from '../src';
import { verifyTdxQuote } from '../src/core/dstack-attestation';
import { createModelQuote } from './fixtures';

jest.mock('@phala/dcap-qvl', () => ({
  Quote: { parse: jest.fn() },
  verify: jest.fn(),
}));

jest.mock('../src/utils/intel-collateral', () => ({
  getIntelCollateral: jest.fn(),
}));

describe('Intel quote verifier configuration', () => {
  const collateral = {} as Awaited<ReturnType<typeof getIntelCollateral>>;
  let verifiedReport: ReturnType<typeof verify>;

  beforeEach(() => {
    jest.resetAllMocks();
    jest.mocked(Quote.parse).mockReturnValue({} as Quote);
    jest.mocked(getIntelCollateral).mockResolvedValue(collateral);
    const quote = createModelQuote();
    verifiedReport = {
      status: quote.tcbStatus,
      advisory_ids: [...quote.advisoryIds],
      ppid: Buffer.alloc(0),
      report: {
        asTd10: () => ({
          reportData: quote.reportData,
          mrConfigId: quote.mrConfigId,
          rtMr3: quote.rtMr3,
          tdAttributes: new Uint8Array(8),
        }),
      },
    } as unknown as ReturnType<typeof verify>;
    jest.mocked(verify).mockReturnValue(verifiedReport);
  });

  test.each([
    ['TDRelaunchAdvised', true],
    ['TDRelaunchAdvisedConfigurationNeeded', false],
  ] as const)('applies TCB policy to %s', async (status, acceptedByDefault) => {
    jest.mocked(verify).mockReturnValue({ ...verifiedReport, status });
    const params = {
      intelQuote: 'abcd',
      verifier: createTdxQuoteVerifier(),
    };
    if (acceptedByDefault) {
      await expect(verifyTdxQuote(params)).resolves.toMatchObject({
        tcbStatus: status,
      });
    } else {
      await expect(verifyTdxQuote(params)).rejects.toMatchObject({
        failure: {
          code: 'policy.tcb_status_not_allowed',
          details: { actual: status },
        },
      });
    }
    await expect(
      verifyTdxQuote({ ...params, policy: { acceptedTcbStatuses: [status] } }),
    ).resolves.toMatchObject({ tcbStatus: status });
  });

  test('fetches collateral from Intel by default in Node.js', async () => {
    const verifyQuote = createTdxQuoteVerifier();
    const quote = await verifyQuote('abcd');

    expect(getIntelCollateral).toHaveBeenCalledWith(
      'https://api.trustedservices.intel.com',
      expect.any(Object),
      expect.any(Object),
      undefined,
    );
    expect(quote).toEqual(createModelQuote());
  });

  test('verifies collateral fetched through a configured PCCS proxy', async () => {
    const verifyQuote = createTdxQuoteVerifier({
      pccsUrl: 'https://app.example.com/api/attestation/intel',
    });
    const quote = await verifyQuote('abcd');

    expect(getIntelCollateral).toHaveBeenCalledWith(
      'https://app.example.com/api/attestation/intel',
      expect.any(Object),
      expect.any(Object),
      undefined,
    );
    expect(verify).toHaveBeenCalledWith(
      expect.any(Uint8Array),
      collateral,
      expect.any(Number),
    );
    expect(quote).toEqual(createModelQuote());
  });

  test('rejects a bad quote before fetching collateral', async () => {
    jest.mocked(Quote.parse).mockImplementation(() => {
      throw new Error('Invalid quote');
    });
    const verifyQuote = createTdxQuoteVerifier();

    await expect(verifyQuote('abcd')).rejects.toMatchObject({
      failure: {
        code: 'quote.verification_failed',
        details: { reason: 'invalid_quote' },
      },
    });
    expect(getIntelCollateral).not.toHaveBeenCalled();
  });

  test('does not accept invalid collateral from a proxy', async () => {
    jest.mocked(verify).mockImplementation(() => {
      throw new Error('Invalid collateral signature');
    });
    const verifyQuote = createTdxQuoteVerifier({
      pccsUrl: '/api/attestation/intel',
    });

    await expect(verifyQuote('abcd')).rejects.toMatchObject({
      failure: {
        code: 'quote.verification_failed',
        details: { reason: 'verifier_error' },
      },
    });
  });
});
