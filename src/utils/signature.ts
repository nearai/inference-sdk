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
  const isHashVerified = compareHash(
    signature.text,
    message.requestBody,
    message.responseBody,
  );
  const isSignatureVerified = verifyChatMessageSignature(signature);
  return {
    isHashVerified,
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
  requestBody: Buffer,
  responseBody: Buffer,
): boolean {
  return text === `${sha256(requestBody)}:${sha256(responseBody)}`;
}
