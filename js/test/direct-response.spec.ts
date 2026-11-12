import {
  findDirectModelAttestationsForSignature,
  type CompletionSignatureReference,
  type SigningAlgo,
  type VerifiedDirectModelAttestation,
} from '../src';
import { createModelAttestation } from './fixtures';

test.each<SigningAlgo>(['ed25519', 'ecdsa'])(
  'selects the complete Direct signer group (%s)',
  (signingAlgo) => {
    const length = signingAlgo === 'ed25519' ? 32 : 20;
    const signer = { signingAlgo, signingAddress: 'ab'.repeat(length) };
    const first: VerifiedDirectModelAttestation = {
      signer,
      tcbStatus: 'UpToDate',
      advisoryIds: [],
      deployment: { appCompose: '{}', runtimeMeasurements: {} },
      deploymentProvenance: 'not_checked',
      gpuEvidence: 'not_provided',
      report: {
        ...createModelAttestation({ signer }),
        modelName: 'test-model',
      },
      modelName: 'test-model',
      instanceId: 'first',
      spkiFingerprint: '11'.repeat(32),
    };
    const second = {
      ...first,
      signer: { ...signer, signingAddress: `0X${'AB'.repeat(length)}` },
      instanceId: 'second',
      spkiFingerprint: '22'.repeat(32),
    };
    const other = {
      ...first,
      signer: { ...signer, signingAddress: 'cd'.repeat(length) },
    };
    const signature: CompletionSignatureReference = {
      kind: 'provider_tee',
      signer,
    };
    const attestations = [other, first, second];
    expect(
      findDirectModelAttestationsForSignature({ attestations, signature }),
    ).toEqual([first, second]);

    for (const [candidates, reference, code] of [
      [[other], signature, 'signature.signer_mismatch'],
      [
        attestations,
        { ...signature, kind: 'gateway' },
        'signature.kind_mismatch',
      ],
      [
        attestations,
        {
          ...signature,
          signer: {
            ...signer,
            signingAlgo: signingAlgo === 'ed25519' ? 'ecdsa' : 'ed25519',
          },
        },
        'signature.signer_mismatch',
      ],
    ] as const) {
      expect(() =>
        findDirectModelAttestationsForSignature({
          attestations: candidates,
          signature: reference,
        }),
      ).toThrow(
        expect.objectContaining({ failure: expect.objectContaining({ code }) }),
      );
    }
  },
);
