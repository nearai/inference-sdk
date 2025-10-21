import {
  ChatMessage,
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
  return verification.isHashVerified && verification.isSignatureVerified;
}

export function verifyChatMessage(
  message: ChatMessage,
  signature: ChatMessageSignature,
): ChatMessageVerification {
  const requestHash = sha256(message.requestBody);
  const responseHash = sha256(message.responseBody);
  const isHashMatched = compareHash(signature.text, requestHash, responseHash);
  const isSignatureVerified = verifyChatMessageSignature(signature);
  return {
    isHashVerified: isHashMatched,
    isSignatureVerified,
  };
}

function verifyChatMessageSignature(signature: ChatMessageSignature): boolean {
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
