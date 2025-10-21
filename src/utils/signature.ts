import {
  ChatMessageSignature,
  ChatMessageVerification,
} from '../types/signature';
import sha256 from 'sha256';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import { trim0x } from './common';

export function isChatMessageVerified(
  verification: ChatMessageVerification,
): boolean {
  return verification.isHashMatched && verification.isSignatureVerified;
}

export function verifyChatMessage(
  signature: ChatMessageSignature,
  { requestBody, responseBody }: { requestBody: Buffer; responseBody: Buffer },
): ChatMessageVerification {
  const requestHash = sha256(requestBody);
  const responseHash = sha256(responseBody);
  const isHashMatched = compareHash(signature.text, requestHash, responseHash);
  const isSignatureVerified = verifySignature(signature);
  return {
    isHashMatched,
    isSignatureVerified,
  };
}

function verifySignature(signature: ChatMessageSignature): boolean {
  if (signature.signing_algo === 'ecdsa') {
    const recoveredAddress = ethers.verifyMessage(
      signature.text,
      signature.signature,
    );
    const recoveredAddressRaw = Buffer.from(trim0x(recoveredAddress), 'hex');
    const signingAddressRaw = Buffer.from(
      trim0x(signature.signing_address),
      'hex',
    );
    return recoveredAddressRaw.equals(signingAddressRaw);
  } else {
    const publicKey = Buffer.from(trim0x(signature.signing_address), 'hex');
    return nacl.sign.detached.verify(
      Buffer.from(signature.text, 'utf-8'),
      Buffer.from(trim0x(signature.signature), 'hex'),
      publicKey,
    );
  }
}

function compareHash(
  text: string,
  requestHash: string,
  responseHash: string,
): boolean {
  return text === `${requestHash}:${responseHash}`;
}
