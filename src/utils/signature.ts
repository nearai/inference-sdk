import {
  ChatMessageSignature,
  ChatMessageVerification,
  VerifyChatMessageParams,
} from '../types/signature';
import sha256 from 'sha256';
import { ethers } from 'ethers';

export function isChatMessageVerified(
  verification: ChatMessageVerification,
): boolean {
  return verification.isHashMatched && verification.isSignatureVerified;
}

export function verifyChatMessage({
  requestBody,
  responseBody,
  signature,
}: VerifyChatMessageParams): ChatMessageVerification {
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
    const recoveredAddressRaw = Buffer.from(
      recoveredAddress.replace('0x', ''),
      'hex',
    );
    const signingAddressRaw = Buffer.from(
      signature.signing_address.replace('0x', ''),
      'hex',
    );
    return recoveredAddressRaw.equals(signingAddressRaw);
  } else {
    throw Error(
      `Unimplemented signature verification for signing algo: ${signature.signing_algo}`,
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
