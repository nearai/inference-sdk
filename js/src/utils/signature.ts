import { Chat, ChatSignature, ChatVerification } from '../types/signature';
import sha256 from 'sha256';
import { ethers } from 'ethers';
import * as nacl from 'tweetnacl';
import { hexToBuffer } from './common';

export function isChatVerified(verification: ChatVerification): boolean {
  return verification.isHashVerified && verification.isSignatureVerified;
}

export function verifyChat(
  message: Chat,
  signature: ChatSignature,
): ChatVerification {
  const isHashVerified = compareHash(
    signature.text,
    message.requestBody,
    message.responseBody,
  );
  const isSignatureVerified = verifyChatSignature(signature);
  return {
    isHashVerified,
    isSignatureVerified,
  };
}

function verifyChatSignature(signature: ChatSignature): boolean {
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
