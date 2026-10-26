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
