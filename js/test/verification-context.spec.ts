import { Buffer } from 'node:buffer';
import { verify } from '@phala/dcap-qvl';
import {
  createTdxQuoteVerifier,
  createVerificationContext,
  type VerificationContext,
  verifyGatewayAttestation,
  verifyModelAttestation,
  verifyDirectModelAttestations,
} from '../src';
import {
  createModelAttestation,
  createModelQuote,
  nonce,
  sha256,
} from './fixtures';
import {
  collateralResponse,
  intelFixtureTime,
  intelQuoteBytes,
  quoteWithOtherFmspc,
} from './intel-fixtures';

jest.mock('@phala/dcap-qvl', () => ({
  ...jest.requireActual('@phala/dcap-qvl'),
  verify: jest.fn(),
}));

describe('shared context through verification entry points', () => {
  const modelBytes = quoteWithOtherFmspc();
  const managerBytes = Buffer.from(intelQuoteBytes);
  managerBytes[100] ^= 1;
  const managerHash = sha256('[]');
  const attestation = createModelAttestation({
    intelQuote: modelBytes.toString('hex'),
    composeManagerAttestation: {
      actions: [],
      actionsHash: managerHash.toString('hex'),
      nonce,
      intelQuote: managerBytes.toString('hex'),
      eventLog: createModelAttestation().eventLog,
    },
  });
  const tdxQuote = createTdxQuoteVerifier({ pccsUrl: 'https://pccs.test' });

  beforeEach(() => {
    jest.spyOn(Date, 'now').mockReturnValue(intelFixtureTime);
    // Only quote facts are synthetic here so the binding/deployment checks can
    // run with the SDK's fixtures. Real DCAP verification has separate coverage.
    jest.mocked(verify).mockImplementation((bytes) => {
      const facts = createModelQuote(
        Buffer.from(bytes).equals(managerBytes)
          ? {
              reportData: Buffer.concat([
                managerHash,
                Buffer.from(nonce, 'hex'),
              ]),
            }
          : {},
      );
      return {
        status: facts.tcbStatus,
        advisory_ids: facts.advisoryIds,
        report: {
          asTd10: () => ({
            reportData: facts.reportData,
            mrConfigId: facts.mrConfigId,
            rtMr3: facts.rtMr3,
            tdAttributes: Buffer.alloc(8),
          }),
        },
      } as unknown as ReturnType<typeof verify>;
    });
  });
  afterEach(() => {
    jest.restoreAllMocks();
    jest.mocked(verify).mockClear();
  });

  async function run(context?: VerificationContext) {
    return Promise.all([
      verifyGatewayAttestation({
        attestation: {
          ...createModelAttestation({
            intelQuote: intelQuoteBytes.toString('hex'),
          }),
          reportedQuoteData: createModelQuote().reportData.toString('hex'),
        },
        clientBinding: { nonce },
        verifiers: { tdxQuote },
        context,
      }),
      verifyModelAttestation({
        attestation,
        clientBinding: { nonce },
        verifiers: { tdxQuote },
        context,
      }),
    ]);
  }

  test('separate Gateway/model calls share downloads through the nested Manager', async () => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => collateralResponse(String(input)));
    const baseline = await run();
    expect(fetch).toHaveBeenCalledTimes(9); // separate Gateway/model operations
    fetch.mockClear();
    jest.mocked(verify).mockClear();
    const result = await run(createVerificationContext());
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(verify).toHaveBeenCalledTimes(3);
    expect(result).toEqual(baseline);
    expect(result[1].deployment.composeManager).toBeDefined();
  });

  test('sequential public calls and a bound verifier share the explicit context', async () => {
    const fetch = jest.fn(async (input: RequestInfo | URL) =>
      collateralResponse(String(input)),
    );
    const context = createVerificationContext({ fetch });
    const bound = createTdxQuoteVerifier({
      pccsUrl: 'https://pccs.test',
      context,
    });
    await verifyGatewayAttestation({
      attestation: {
        ...createModelAttestation({
          intelQuote: intelQuoteBytes.toString('hex'),
        }),
        reportedQuoteData: createModelQuote().reportData.toString('hex'),
      },
      clientBinding: { nonce },
      verifiers: { tdxQuote: bound },
    });
    await verifyModelAttestation({
      attestation,
      clientBinding: { nonce },
      verifiers: { tdxQuote: bound },
    });
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(verify).toHaveBeenCalledTimes(3);
  });

  test('direct replicas and their nested Manager automatically share an operation', async () => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => collateralResponse(String(input)));
    const first = { ...attestation, modelName: 'model', instanceId: 'first' };
    const second = { ...first, instanceId: 'second' };
    const result = await verifyDirectModelAttestations({
      servingAttestation: first,
      attestations: [first, second],
      clientBinding: { nonce },
      verifiers: { tdxQuote },
    });
    expect(result.attestations).toHaveLength(2);
    expect(fetch).toHaveBeenCalledTimes(5);
    expect(verify).toHaveBeenCalledTimes(4);
  });

  test('nonce and policy failures remain independent of warm material', async () => {
    const fetch = jest
      .spyOn(globalThis, 'fetch')
      .mockImplementation(async (input) => collateralResponse(String(input)));
    const context = createVerificationContext();
    await run(context);
    await expect(
      verifyModelAttestation({
        attestation,
        clientBinding: { nonce: 'ff'.repeat(32) },
        verifiers: { tdxQuote },
        context,
      }),
    ).rejects.toMatchObject({ failure: { code: 'binding.nonce_mismatch' } });
    await expect(
      verifyModelAttestation({
        attestation,
        clientBinding: { nonce },
        policy: { acceptedTcbStatuses: ['OutOfDate'] },
        verifiers: { tdxQuote },
        context,
      }),
    ).rejects.toMatchObject({
      failure: { code: 'policy.tcb_status_not_allowed' },
    });
    expect(fetch).toHaveBeenCalledTimes(5);
  });
});
