import { Chat, ChatSignature } from '../types/chat';
import sha256 from 'sha256';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import { hexToBuffer } from '../utils/common';
import { VerificationError } from '../utils/errors';
import { Buffer } from 'buffer';
import { ModelAttestation } from '../types/attestation-model';

export function verifyChat(message: Chat, signature: ChatSignature) {
  verifyChatHash(signature.text, message.requestBody, message.responseBody);
  verifyChatSignature(signature);
}

export function verifySigningAddress(
  signature: ChatSignature,
  attestations: ModelAttestation[],
) {
  const modelAttestation = attestations.find((attestation) => {
    return (
      signature.signing_algo === attestation.signing_algo &&
      hexToBuffer(signature.signing_address).equals(
        hexToBuffer(attestation.signing_address),
      )
    );
  });

  if (!modelAttestation) {
    throw new VerificationError(
      'The signature signing algorithm or address does not match any of the model attestations',
    );
  }
}

function verifyChatSignature(signature: ChatSignature) {
  if (signature.signing_algo === 'ecdsa') {
    const recoveredAddress = ethers.verifyMessage(
      signature.text,
      signature.signature,
    );
    const recoveredAddressRaw = hexToBuffer(recoveredAddress);
    const signingAddressRaw = hexToBuffer(signature.signing_address);
    if (!recoveredAddressRaw.equals(signingAddressRaw)) {
      throw new VerificationError('Invalid ECDSA chat signature');
    }
  } else {
    const publicKey = hexToBuffer(signature.signing_address);
    const verified = nacl.sign.detached.verify(
      Buffer.from(signature.text),
      hexToBuffer(signature.signature),
      publicKey,
    );
    if (!verified) {
      throw new VerificationError('Invalid ED25519 chat signature');
    }
  }
}

function verifyChatHash(
  text: string,
  requestBody: Buffer,
  responseBody: Buffer,
) {
  const expected = `${sha256(requestBody)}:${sha256(responseBody)}`;
  if (text !== expected) {
    throw new VerificationError('Chat hash mismatching');
  }
}
