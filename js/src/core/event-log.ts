import { Buffer } from 'buffer';
import * as v from 'valibot';
import {
  type DstackEventLogEntrySchema,
  DstackEventLogSchema,
  SerializedDstackEventLogSchema,
} from '../schemas';
import type { AttestationEventLog } from '../types/attestation-common';
import type { RuntimeMeasurements } from '../types/verification';
import { VerificationError } from '../utils/errors';
import { sha384, trimHexPrefix, utf8 } from '../utils/common';

// dstack reserves this event type for runtime payloads, whose digest must be
// recomputed from the payload rather than trusted from the event log.
const DSTACK_RUNTIME_EVENT_TYPE = 0x08000001;

type EventLogEntry = v.InferOutput<typeof DstackEventLogEntrySchema> & {
  path: string;
};
type DecodeEventHexParams = {
  value: string;
  path: string;
  allowEmpty: boolean;
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
      code: 'measurement.rtmr3_mismatch',
      details: { reason: 'no_events' },
    });
  }
  if (!Buffer.from(replayed).equals(expected)) {
    throw new VerificationError({
      code: 'measurement.rtmr3_mismatch',
      details: { reason: 'replay_mismatch' },
    });
  }

  return { osImageHash, composeHash };
}

function parseEventLog(eventLog: AttestationEventLog): EventLogEntry[] {
  const schema =
    typeof eventLog === 'string'
      ? SerializedDstackEventLogSchema
      : DstackEventLogSchema;
  const parsed = v.safeParse(schema, eventLog);
  if (!parsed.success) {
    throw invalidEventLogSchema(parsed.issues[0]);
  }

  return parsed.output.map((entry, index) => ({
    ...entry,
    path: `eventLog[${index}]`,
  }));
}

function invalidEventLogSchema(issue: v.BaseIssue<unknown>): VerificationError {
  if (issue.type === 'parse_json') {
    return new VerificationError({
      code: 'measurement.event_log_invalid',
      details: { path: 'eventLog', reason: 'invalid_json' },
    });
  }

  const dotPath = v.getDotPath(issue);
  const path = !dotPath
    ? 'eventLog'
    : dotPath.startsWith('[')
      ? `eventLog${dotPath}`
      : `eventLog.${dotPath}`.replace(/\.(\d+)(?=\.|$)/g, '[$1]');
  return new VerificationError({
    code: 'measurement.event_log_invalid',
    details: {
      path,
      reason: 'invalid_type',
      expected: issue.expected ?? 'valid event log',
    },
  });
}

async function eventDigest(entry: EventLogEntry): Promise<Buffer> {
  if (entry.event_type === DSTACK_RUNTIME_EVENT_TYPE) {
    const payload = decodeEventHex({
      value: entry.event_payload,
      path: `${entry.path}.event_payload`,
      allowEmpty: true,
    });
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
      const stored = decodeEventHex({
        value: entry.digest,
        path: `${entry.path}.digest`,
        allowEmpty: false,
      });
      if (stored.length !== 48 || !stored.equals(computed)) {
        throw new VerificationError({
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
  const digest = decodeEventHex({
    value: entry.digest,
    path: `${entry.path}.digest`,
    allowEmpty: false,
  });
  if (digest.length !== 48) {
    throw new VerificationError({
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
function decodeEventHex({
  value,
  path,
  allowEmpty,
}: DecodeEventHexParams): Buffer {
  const normalized = trimHexPrefix(value);
  if (
    (!allowEmpty && normalized.length === 0) ||
    normalized.length % 2 !== 0 ||
    !/^[0-9a-fA-F]*$/.test(normalized)
  ) {
    throw new VerificationError({
      code: 'measurement.event_log_invalid',
      details: { path, reason: 'invalid_hex' },
    });
  }
  return Buffer.from(normalized, 'hex');
}
