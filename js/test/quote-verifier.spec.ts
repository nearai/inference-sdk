import { Buffer } from 'node:buffer';
import { Quote, getCollateral, verify } from '@phala/dcap-qvl';
import { createDcapQuoteVerifier } from '../src';
import { createModelQuote } from './fixtures';

jest.mock('@phala/dcap-qvl', () => ({
  Quote: { parse: jest.fn() },
  getCollateral: jest.fn(),
  verify: jest.fn(),
}));

describe('Intel quote verifier configuration', () => {
  const collateral = {} as Awaited<ReturnType<typeof getCollateral>>;

  beforeEach(() => {
    jest.resetAllMocks();
    jest.mocked(getCollateral).mockResolvedValue(collateral);
    const quote = createModelQuote();
    jest.mocked(verify).mockReturnValue({
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
    } as unknown as ReturnType<typeof verify>);
  });

  test('uses Intel collateral by default', async () => {
    const verifyQuote = createDcapQuoteVerifier();
    const quote = await verifyQuote('abcd');

    expect(getCollateral).toHaveBeenCalledWith(
      'https://api.trustedservices.intel.com',
      expect.any(Uint8Array),
    );
    expect(quote).toEqual(createModelQuote());
  });

  test('verifies collateral fetched through a configured PCCS proxy', async () => {
    const verifyQuote = createDcapQuoteVerifier({
      pccsUrl: 'https://app.example.com/api/attestation/intel',
    });
    const quote = await verifyQuote('abcd');

    expect(getCollateral).toHaveBeenCalledWith(
      'https://app.example.com/api/attestation/intel',
      expect.any(Uint8Array),
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
    const verifyQuote = createDcapQuoteVerifier();

    await expect(verifyQuote('abcd')).rejects.toMatchObject({
      failure: {
        code: 'quote.verification_failed',
        details: { reason: 'invalid_quote' },
      },
    });
    expect(getCollateral).not.toHaveBeenCalled();
  });

  test('does not accept invalid collateral from a proxy', async () => {
    jest.mocked(verify).mockImplementation(() => {
      throw new Error('Invalid collateral signature');
    });
    const verifyQuote = createDcapQuoteVerifier({
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
