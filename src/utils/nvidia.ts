import {
  NvidiaGpuJwtPayload,
  NvidiaGpuVerificationRaw,
  NvidiaJwtPayload,
  NvidiaGpuVerification
} from "../types/nvidia";
import { decodeJwt } from "jose";
import { mapRecord } from "./common";

export function isNvidiaGpuVerified(verification: NvidiaGpuVerification): boolean {
  return verification.JWT["x-nvidia-overall-att-result"];
}

export async function verifyNvidiaGpu(payload: string): Promise<NvidiaGpuVerification> {
  const response = await fetch(
    "https://nras.attestation.nvidia.com/v3/attest/gpu",
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: payload,
    }
  );

  if (!response.ok) {
    throw Error(`Get GPU attestation failed with status code ${response.status}`);
  }

  const verification = await response.json();

  return parseNvidiaGpuVerification(verification);
}

function parseNvidiaGpuVerification(verification: NvidiaGpuVerificationRaw): NvidiaGpuVerification {
  return {
    JWT: decodeJwt(verification[0][1]) as NvidiaJwtPayload,
    GPU: mapRecord(verification[1], (key, value) => decodeJwt(value) as NvidiaGpuJwtPayload),
  }
}
