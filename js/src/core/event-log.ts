import { Buffer } from 'buffer';
import type { AttestationEventLog } from '../types/attestation-common';
import type { RuntimeMeasurements } from '../types/verification';
import { VerificationError } from '../utils/errors';
import { sha384, trimHexPrefix, utf8 } from '../utils/common';

// dstack reserves this event type for runtime payloads, whose digest must be
// recomputed from the payload rather than trusted from the event log.
const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

type EventLogEntry = {
  path: string;
  digest: string;
  event_type?: number;
  event: string;
  event_payload: string;
  imr: number;
};

/**
 * Replay RTMR3 from the dstack event log. Runtime event payloads are hashed
 * again before extending the register, preventing payload substitution with a
 * copied digest. Other event types remain replayable for compatibility, but
 * cannot supply runtime metadata because their name and payload are not bound
 * by this verifier.
 */
export async function verifyAndReplayRtmr3(
  eventLog: AttestationEventLog,
  quotedRtmr3: Uint8Array,
): Promise<RuntimeMeasurements> {
  const events = parseEventLog(eventLog);
  const expected = Buffer.from(quotedRtmr3);
  if (expected.length !== 48) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.rtmr3_mismatch',
      details: {
        reason: 'wrong_length',
        expectedBytes: 48,
        actualBytes: expected.length,
      },
    });
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

    // Only dstack runtime events authenticate the event name and payload: the
    // digest is recomputed from both values in eventDigest(). A legacy or
    // other event type contributes to RTMR3 replay, but its JSON metadata is
    // not authenticated and must not be exposed as a measured value.
    if (entry.event_type === DSTACK_RUNTIME_EVENT_TYPE) {
      if (entry.event === 'os-image-hash') {
        osImageHash = entry.event_payload;
      } else if (entry.event === 'compose-hash') {
        composeHash = entry.event_payload;
      }
    }
  }

  if (count === 0) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.rtmr3_mismatch',
      details: { reason: 'no_events' },
    });
  }
  if (!Buffer.from(replayed).equals(expected)) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.rtmr3_mismatch',
      details: { reason: 'replay_mismatch' },
    });
  }

  return { osImageHash, composeHash };
}

function parseEventLog(eventLog: AttestationEventLog): EventLogEntry[] {
  let parsed: unknown = eventLog;
  if (typeof parsed === 'string') {
    try {
      parsed = JSON.parse(parsed);
    } catch (cause) {
      throw new VerificationError(
        {
          phase: 'measurement',
          code: 'measurement.event_log_invalid',
          details: { path: 'eventLog', reason: 'invalid_json' },
        },
        { cause },
      );
    }
  }
  if (!Array.isArray(parsed)) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: {
        path: 'eventLog',
        reason: 'invalid_type',
        expected: 'array',
      },
    });
  }

  return parsed.map((value, index) => parseEventLogEntry(value, index));
}

function parseEventLogEntry(value: unknown, index: number): EventLogEntry {
  const path = `eventLog[${index}]`;
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: { path, reason: 'invalid_type', expected: 'object' },
    });
  }
  const record = value as Record<string, unknown>;
  const digest = requireString(record, 'digest', index);
  const event = optionalString(record, 'event', index) ?? '';
  const eventPayload = optionalString(record, 'event_payload', index) ?? '';
  const imr = requireNumber(record, 'imr', index);
  const eventType = record.event_type;
  if (eventType !== undefined && !isU32(eventType)) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: {
        path: `${path}.event_type`,
        reason: 'invalid_type',
        expected: 'unsigned 32-bit integer',
      },
    });
  }
  return {
    path,
    digest,
    event,
    event_payload: eventPayload,
    imr,
    event_type: eventType ?? 0,
  };
}

async function eventDigest(entry: EventLogEntry): Promise<Buffer> {
  if (entry.event_type === DSTACK_RUNTIME_EVENT_TYPE) {
    const payload = decodeEventHex(
      entry.event_payload,
      `${entry.path}.event_payload`,
      true,
    );
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
      const stored = decodeEventHex(
        entry.digest,
        `${entry.path}.digest`,
        false,
      );
      if (stored.length !== 48 || !stored.equals(computed)) {
        throw new VerificationError({
          phase: 'measurement',
          code: 'measurement.event_log_invalid',
          details: {
            path: `${entry.path}.digest`,
            reason: stored.length === 48 ? 'digest_mismatch' : 'wrong_length',
            ...(stored.length === 48
              ? {}
              : { expectedBytes: 48, actualBytes: stored.length }),
          },
        });
      }
    }
    return computed;
  }

  // dstack event-log digests are SHA-384 values, so a malformed length is
  // rejected even though replaying a shorter byte string would be possible.
  const digest = decodeEventHex(entry.digest, `${entry.path}.digest`, false);
  if (digest.length !== 48) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: {
        path: `${entry.path}.digest`,
        reason: 'wrong_length',
        expectedBytes: 48,
        actualBytes: digest.length,
      },
    });
  }
  return digest;
}

/** dstack runtime events may legitimately carry an empty payload. */
function decodeEventHex(
  value: string,
  path: string,
  allowEmpty: boolean,
): Buffer {
  const normalized = trimHexPrefix(value);
  if (
    (!allowEmpty && normalized.length === 0) ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]*$/.test(normalized)
  ) {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: { path, reason: 'invalid_hex' },
    });
  }
  return Buffer.from(normalized, 'hex');
}

function requireString(
  record: Record<string, unknown>,
  field: string,
  index: number,
): string {
  const value = record[field];
  if (typeof value !== 'string') {
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: {
        path: `eventLog[${index}].${field}`,
        reason: 'invalid_type',
        expected: 'string',
      },
    });
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
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: {
        path: `eventLog[${index}].${field}`,
        reason: 'invalid_type',
        expected: 'string',
      },
    });
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
    throw new VerificationError({
      phase: 'measurement',
      code: 'measurement.event_log_invalid',
      details: {
        path: `eventLog[${index}].${field}`,
        reason: 'invalid_type',
        expected: 'unsigned 32-bit integer',
      },
    });
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
