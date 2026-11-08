# Responses transport fixtures

`response.json` and `response.sse` contain test inputs with text, function
calls and multibyte UTF-8. Tests sign the exact fixture bytes, including the SSE
framing and trailing bytes after `[DONE]`.
