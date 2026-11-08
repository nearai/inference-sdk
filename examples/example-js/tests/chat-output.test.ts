import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ChatStreamOutput, readChatOutput } from '../utils/chat-output.ts';

test('rejects error events and invalid or conflicting completion IDs', async () => {
  for (const event of [
    { error: 'failed' },
    { type: 'error', message: 'failed' },
  ]) {
    const wire = `data: ${JSON.stringify(event)}\n\ndata: [DONE]\n\n`;
    await assert.rejects(
      readChatOutput(new Response(wire), true),
      /Stream returned an error/,
    );
  }
  for (const id of ['chat-other', '', 17]) {
    const wire = `data: {"id":"chat-first"}\n\ndata: ${JSON.stringify({ id })}\n\n`;
    await assert.rejects(
      readChatOutput(new Response(wire), true),
      /completion ID/i,
    );
  }
});

test('validates the final event at EOF and ignores bytes after DONE', async () => {
  const wire = 'data: {"id":"chat-1"}';
  assert.equal((await readChatOutput(new Response(wire), true)).id, 'chat-1');
  const invalid = Buffer.from('data: {"id":"chat-1","extra":"\xff"}', 'latin1');
  await assert.rejects(readChatOutput(new Response(invalid), true), TypeError);
  const tail = Buffer.from(`${wire}\n\ndata: [DONE]\n\ndata: \xff`, 'latin1');
  assert.equal((await readChatOutput(new Response(tail), true)).id, 'chat-1');
});

for (const separator of ['\n', '\r\n', '\r']) {
  test(`incremental Chat output with ${JSON.stringify(separator)} records`, () => {
    const record = Buffer.from(
      [
        'data: {"id":"chat-fixture",',
        'data: "choices":[{"delta":{"content":"Hello 🌍"}}]}',
        '',
        ':',
      ].join(separator),
    );
    for (let split = 0; split <= record.length; split++) {
      const output = new ChatStreamOutput();
      const text =
        output.push(record.subarray(0, split)) +
        output.push(record.subarray(split));
      assert.equal(text, 'Hello 🌍');
      assert.equal(output.done, false);
      output.push(
        Buffer.from(
          `${separator}${separator}data: [DONE]${separator}${separator}`,
        ),
        true,
      );
      assert.equal(output.done, true);
      assert.equal(output.id, 'chat-fixture');
    }
  });
}

test('removes only the initial BOM across byte boundaries', () => {
  const event =
    'data: {"id":"chat-fixture","choices":[{"delta":{"content":"Hello 🌍"}}]}\n\n';
  for (const prefix of [
    '\uFEFF',
    '\uFEFF\uFEFFdata: {"error":"ignored"}\n\n',
    ': first\n\n\uFEFFdata: {"error":"ignored"}\n\n',
  ]) {
    const record = Buffer.from(prefix + event);
    for (let split = 0; split <= record.length; split++) {
      const output = new ChatStreamOutput();
      assert.equal(
        output.push(record.subarray(0, split)) +
          output.push(record.subarray(split)),
        'Hello 🌍',
      );
      assert.equal(output.id, 'chat-fixture');
    }
  }
});
