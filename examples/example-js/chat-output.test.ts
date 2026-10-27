import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ChatStreamOutput, chatOutput } from './chat-output.ts';

for (const separator of ['\n', '\r\n', '\r']) {
  test(`incremental Chat output with ${JSON.stringify(separator)} records`, () => {
    const record = [
      'data: {"id":"chat-fixture",',
      'data: "choices":[{"delta":{"content":"Hello 🌍"}}]}',
      '',
      '',
    ].join(separator);
    for (let split = 0; split <= record.length; split++) {
      const output = new ChatStreamOutput();
      const text =
        output.push(record.slice(0, split)) +
        output.push(record.slice(split)) +
        output.push('', true);
      assert.equal(text, 'Hello 🌍');
      assert.equal(output.done, false); // Text is available before the terminal record.
      assert.equal(
        output.push(`data: [DONE]${separator}${separator}`, true),
        '',
      );
      assert.equal(output.done, true);
      assert.equal(output.id, 'chat-fixture');
    }
    assert.deepEqual(
      chatOutput(`${record}data: [DONE]${separator}${separator}`, true),
      { id: 'chat-fixture', text: 'Hello 🌍' },
    );
    assert.throws(() => chatOutput(record, true), /without \[DONE\]/);
  });
}

test('removes only the initial BOM across chunks', async () => {
  const event =
    'data: {"id":"chat-fixture","choices":[{"delta":{"content":"Hello 🌍"}}]}\n\n';
  for (const prefix of [
    '\uFEFF',
    '\uFEFF\uFEFFdata: {"error":"ignored"}\n\n',
    ': first\n\n\uFEFFdata: {"error":"ignored"}\n\n',
  ]) {
    const record = prefix + event;
    for (let split = 0; split <= record.length; split++) {
      const output = new ChatStreamOutput();
      assert.equal(
        output.push(record.slice(0, split)) + output.push(record.slice(split)),
        'Hello 🌍',
      );
      assert.equal(output.id, 'chat-fixture');
      assert.equal(output.done, false);
    }
    const source = new ReadableStream<BufferSource>({
      start(controller) {
        for (const byte of new TextEncoder().encode(record))
          controller.enqueue(new Uint8Array([byte]));
        controller.close();
      },
    });
    const output = new ChatStreamOutput();
    let text = '';
    for await (const chunk of source.pipeThrough(
      new TextDecoderStream('utf-8', { ignoreBOM: true }),
    ))
      text += output.push(chunk);
    assert.equal(text + output.push('', true), 'Hello 🌍');
    assert.equal(output.id, 'chat-fixture');
  }
});
