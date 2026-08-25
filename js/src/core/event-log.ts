import { JsonValue } from '../types/attestation-common';
import { VerifiedRuntimeMeasurements } from '../types/verification';
import { VerificationError } from '../utils/errors';
import { hexToBuffer, sha384, utf8 } from '../utils/common';

const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

type EventLogEntry = {
  digest: string;
  event_type?: number;
  event: string;
  event_payload: string;
  imr: number;
};

/**
 * Replay RTMR3 from the dstack event log. Runtime event payloads are hashed
 * again before extending the register, preventing payload substitution with a
 * copied digest.
 */
export async function verifyAndReplayRtmr3(
  eventLog: JsonValue,
  quotedRtmr3: Uint8Array,
): Promise<VerifiedRuntimeMeasurements> {
  const events = parseEventLog(eventLog);
  const expected = Buffer.from(quotedRtmr3);
  if (expected.length !== 48) {
    throw new VerificationError(
      `quote RTMR3 must be 48 bytes, got ${expected.length}`,
    );
  }

  let replayed: Uint8Array = Buffer.alloc(48);
  let count = 0;
  let osImageHash: string | undefined;
  let composeHash: string | undefined;

  for (const entry of events) {
    if (entry.imr !== 3) {
      continue;
    }
    count += 1;
    const digest = await eventDigest(entry);
    replayed = await sha384(Buffer.concat([replayed, digest]));

    if (entry.event === 'os-image-hash') {
      osImageHash = entry.event_payload;
    } else if (entry.event === 'compose-hash') {
      composeHash = entry.event_payload;
    }
  }

  if (count === 0) {
    throw new VerificationError('event log contains no RTMR3 events');
  }
  if (!Buffer.from(replayed).equals(expected)) {
    throw new VerificationError('event log RTMR3 replay does not match quote');
  }

  return { osImageHash, composeHash };
}

function parseEventLog(eventLog: JsonValue): EventLogEntry[] {
  let parsed: unknown = eventLog;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch (cause) {
      throw new VerificationError('event_log is not valid JSON', cause);
    }
  }
  if (!Array.isArray(parsed)) {
    throw new VerificationError('event_log must be a JSON array');
  }

  return parsed.map((value, index) => parseEventLogEntry(value, index));
}

function parseEventLogEntry(value: unknown, index: number): EventLogEntry {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new VerificationError(`event_log[${index}] must be an object`);
  }
  const record = value as Record<string, unknown>;
  const digest = requireString(record, 'digest', index);
  const event = optionalString(record, 'event', index) ?? '';
  const eventPayload = optionalString(record, 'event_payload', index) ?? '';
  const imr = requireNumber(record, 'imr', index);
  const eventType = record.event_type;
  if (eventType !== undefined && !isU32(eventType)) {
    throw new VerificationError(
      `event_log[${index}].event_type must be an unsigned 32-bit integer`,
    );
  }
  return {
    digest,
    event,
    event_payload: eventPayload,
    imr,
    event_type: eventType ?? 0,
  };
}

async function eventDigest(entry: EventLogEntry): Promise<Buffer> {
  if (entry.event_type === DSTACK_RUNTIME_EVENT_TYPE) {
    const payload = decodeEventHex(entry.event_payload);
    const eventType = Buffer.alloc(4);
    eventType.writeUInt32LE(DSTACK_RUNTIME_EVENT_TYPE);
    const computed = await sha384(
      Buffer.concat([
        eventType,
        utf8(':'),
        utf8(entry.event),
        utf8(':'),
        payload,
      ]),
    );

    if (entry.digest.length > 0) {
      const stored = hexToBuffer(entry.digest);
      if (stored.length !== 48 || !stored.equals(computed)) {
        throw new VerificationError(
          `runtime event '${entry.event}' digest does not match its payload`,
        );
      }
    }
    return computed;
  }

  // dstack event-log digests are SHA-384 values, so a malformed length is
  // rejected even though replaying a shorter byte string would be possible.
  const digest = hexToBuffer(entry.digest);
  if (digest.length !== 48) {
    throw new VerificationError(
      `event '${entry.event}' digest must be 48 bytes, got ${digest.length}`,
    );
  }
  return digest;
}

/** dstack runtime events may legitimately carry an empty payload. */
function decodeEventHex(value: string): Buffer {
  return value === '' ? Buffer.alloc(0) : hexToBuffer(value);
}

function requireString(
  record: Record<string, unknown>,
  field: string,
  index: number,
): string {
  const value = record[field];
  if (typeof value !== 'string') {
    throw new VerificationError(
      `event_log[${index}].${field} must be a string`,
    );
  }
  return value;
}

function optionalString(
  record: Record<string, unknown>,
  field: string,
  index: number,
): string | undefined {
  const value = record[field];
  if (value === undefined) {
    return undefined;
  }
  if (typeof value !== 'string') {
    throw new VerificationError(
      `event_log[${index}].${field} must be a string`,
    );
  }
  return value;
}

function requireNumber(
  record: Record<string, unknown>,
  field: string,
  index: number,
): number {
  const value = record[field];
  if (!isU32(value)) {
    throw new VerificationError(
      `event_log[${index}].${field} must be an unsigned 32-bit integer`,
    );
  }
  return value;
}

function isU32(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= 0xffffffff
  );
}
