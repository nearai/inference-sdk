jest.mock('@phala/dcap-qvl', () => {
  const actual =
    jest.requireActual<typeof import('@phala/dcap-qvl')>('@phala/dcap-qvl');
  return { ...actual, getCollateral: jest.fn() };
});

import { getCollateral } from '@phala/dcap-qvl';
import { verifyDcapQuote } from '../../src/utils/intel';

describe('Intel DCAP quote verification', () => {
  test('rejects a structurally malformed quote before requesting collateral', async () => {
    await expect(verifyDcapQuote('00')).rejects.toMatchObject({
      failure: {
        phase: 'quote',
        code: 'quote.verification_failed',
        details: { reason: 'invalid_quote' },
      },
      retryable: false,
    });

    expect(getCollateral).not.toHaveBeenCalled();
  });
});
