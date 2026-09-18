export type SseLine = {
  readonly content: string;
  readonly ending: string;
};

type CompleteSseRecord = {
  /** Event lines, including the final line ending. */
  readonly value: string;
  /** The blank line ending that terminates the event. */
  readonly separator: string;
};

type CompleteSseRecords = {
  readonly records: readonly CompleteSseRecord[];
  readonly pending: string;
};

/** Split complete events without treating the CR and LF in CRLF as two lines. */
export function takeCompleteSseRecords(value: string): CompleteSseRecords {
  const records: CompleteSseRecord[] = [];
  let recordStart = 0;
  let lineStart = 0;
  let index = 0;
  while (index < value.length) {
    if (value[index] !== '\r' && value[index] !== '\n') {
      index += 1;
      continue;
    }
    // A trailing CR may be the first half of a CRLF split across chunks.
    if (value[index] === '\r' && index + 1 === value.length) break;
    const lineEnd = index;
    index += value[index] === '\r' && value[index + 1] === '\n' ? 2 : 1;
    if (lineEnd === lineStart) {
      records.push({
        value: value.slice(recordStart, lineStart),
        separator: value.slice(lineStart, index),
      });
      recordStart = index;
    }
    lineStart = index;
  }
  return { records, pending: value.slice(recordStart) };
}

export function splitSseLines(value: string): SseLine[] {
  const lines: SseLine[] = [];
  let start = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== '\n' && value[index] !== '\r') continue;
    const isCrLf = value[index] === '\r' && value[index + 1] === '\n';
    const ending = isCrLf ? '\r\n' : value[index];
    lines.push({ content: value.slice(start, index), ending });
    start = index + ending.length;
    if (isCrLf) index += 1;
  }
  if (start < value.length) {
    lines.push({ content: value.slice(start), ending: '' });
  }
  return lines;
}

export function getSseData(line: string): string | undefined {
  if (line === 'data') return '';
  if (!line.startsWith('data:')) return undefined;
  const value = line.slice('data:'.length);
  return value.startsWith(' ') ? value.slice(1) : value;
}

/** Read event payloads from a complete response body, joining its data lines. */
export function getSseDataRecords(text: string): string[] {
  const { records, pending } = takeCompleteSseRecords(text);
  const values = records.map((record) => record.value);
  if (pending.length > 0) values.push(pending);
  return values.map((value) =>
    splitSseLines(value)
      .map((line) => getSseData(line.content))
      .filter((data) => data !== undefined)
      .join('\n'),
  );
}
