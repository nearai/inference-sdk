/** Decode complete Chat SSE records while retaining partial UTF-8 text/CRLF. */
export class ChatStreamOutput {
  private pending = Buffer.alloc(0);
  private decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
  private started = false;
  id = '';
  done = false;

  push(chunk: Uint8Array, eof = false): string {
    if (this.done) return '';
    this.pending = Buffer.concat(
      eof ? [this.pending, chunk, Buffer.from('\n\n')] : [this.pending, chunk],
    );
    let text = '';
    let start = 0;
    let line = 0;
    for (let index = 0; index < this.pending.length; index++) {
      const char = this.pending[index];
      if (char !== 13 && char !== 10) continue;
      if (char === 13 && index + 1 === this.pending.length && !eof) break;
      const end =
        index + (char === 13 && this.pending[index + 1] === 10 ? 2 : 1);
      if (index === line) {
        const values: string[] = [];
        let event = '';
        let record = this.decoder.decode(this.pending.subarray(start, end));
        if (!this.started) {
          record = record.replace(/^\uFEFF/, '');
          this.started = true;
        }
        for (const line of record.split(/\r\n|\r|\n/)) {
          if (line === 'data') values.push('');
          else if (line.startsWith('data:'))
            values.push(line.slice(5).replace(/^ /, ''));
          else if (line === 'event') event = '';
          else if (line.startsWith('event:'))
            event = line.slice(6).replace(/^ /, '');
        }
        if (event === 'error') throw new Error('Stream returned an error');
        const data = values.join('\n');
        if (data === '[DONE]') {
          this.done = true;
          this.pending = Buffer.alloc(0);
          return text;
        } else if (data) {
          const value = JSON.parse(data);
          if ('error' in value || value.type === 'error')
            throw new Error('Stream returned an error');
          if ('id' in value) {
            if (typeof value.id !== 'string' || !value.id)
              throw new Error('Invalid completion ID');
            if (this.id && this.id !== value.id)
              throw new Error('Conflicting completion IDs');
            this.id = value.id;
          }
          text += value.choices?.[0]?.delta?.content ?? '';
        }
        start = end;
      }
      line = end;
      index = end - 1;
    }
    this.pending = this.pending.subarray(start);
    return text;
  }
}

export async function readChatOutput(
  response: Response,
  stream: boolean,
): Promise<{ id: string; text?: string }> {
  if (!stream) {
    const value = await response.json();
    if (!value.id) throw new Error('Missing completion ID');
    return { id: value.id, text: value.choices?.[0]?.message?.content ?? '' };
  }
  if (!response.body) throw new Error('Streaming Chat response has no body');
  const output = new ChatStreamOutput();
  for await (const chunk of response.body)
    process.stdout.write(output.push(chunk));
  process.stdout.write(output.push(Buffer.alloc(0), true));
  process.stdout.write('\n');
  if (!output.id) throw new Error('Missing completion ID');
  return { id: output.id };
}
