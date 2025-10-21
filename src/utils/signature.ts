import {
  ChatMessage,
  ChatMessageSignature,
  ChatMessageVerification,
} from '../types/signature';
import sha256 from 'sha256';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import { hexToBuffer } from './common';

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
    const recoveredAddressRaw = hexToBuffer(recoveredAddress);
    const signingAddressRaw = hexToBuffer(signature.signing_address);
    return recoveredAddressRaw.equals(signingAddressRaw);
  } else {
    const publicKey = hexToBuffer(signature.signing_address);
    return nacl.sign.detached.verify(
      Buffer.from(signature.text),
      hexToBuffer(signature.signature),
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
