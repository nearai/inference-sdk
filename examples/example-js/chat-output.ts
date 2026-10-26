/** Decode complete Chat SSE records while retaining partial UTF-8 text/CRLF. */
export class ChatStreamOutput {
  private pending = '';
  private started = false;
  id = '';
  done = false;

  push(chunk: string, eof = false): string {
    this.pending += chunk;
    if (!this.started && this.pending) {
      this.pending = this.pending.replace(/^\uFEFF/, '');
      this.started = true;
    }
    let text = '';
    let start = 0;
    let line = 0;
    for (let index = 0; index < this.pending.length; index++) {
      const char = this.pending[index];
      if (char !== '\r' && char !== '\n') continue;
      if (char === '\r' && index + 1 === this.pending.length && !eof) break;
      const end =
        index + (char === '\r' && this.pending[index + 1] === '\n' ? 2 : 1);
      if (index === line) {
        const data = this.pending
          .slice(start, end)
          .split(/\r\n|\r|\n/)
          .flatMap((value) =>
            value === 'data'
              ? ['']
              : value.startsWith('data:')
                ? [value.slice(5).replace(/^ /, '')]
                : [],
          )
          .join('\n');
        if (data === '[DONE]') this.done = true;
        else if (data) {
          const value = JSON.parse(data);
          if (value.error) throw new Error('Stream returned an error');
          if (value.id) {
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
    this.pending = this.pending.slice(start);
    return text;
  }
}

/** Read the receipt ID after EOF; streaming text has already been displayed. */
export function chatOutput(
  text: string,
  stream: boolean,
): { id: string; text: string } {
  if (stream) {
    const output = new ChatStreamOutput();
    const value = output.push(text, true);
    if (!output.done) throw new Error('Stream ended without [DONE]');
    if (!output.id) throw new Error('Missing completion ID');
    return { id: output.id, text: value };
  }
  const value = JSON.parse(text);
  if (!value.id) throw new Error('Missing completion ID');
  return { id: value.id, text: value.choices?.[0]?.message?.content ?? '' };
}
