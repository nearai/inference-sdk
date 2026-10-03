package nearai

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"sync"
)

// sseReader preserves exact record separators, including lone CR and split CRLF.
// Capture occurs below this layer so signature verification uses wire bytes.
type sseReader struct {
	source    io.ReadCloser
	reader    *bufio.Reader
	transform func([]byte) ([]byte, error)
	finish    func() error
	pending   []byte
	ended     bool
	closeOnce sync.Once
	limit     int64
}

func (s *sseReader) record() ([]byte, error) {
	var raw bytes.Buffer
	lineBytes := 0
	for {
		b, e := s.reader.ReadByte()
		if e != nil {
			if e == io.EOF && raw.Len() > 0 {
				return raw.Bytes(), nil
			}
			return nil, e
		}
		raw.WriteByte(b)
		if int64(raw.Len()) > s.limit {
			return nil, failure("api.body_too_large", nil)
		}
		if b == '\r' || b == '\n' {
			if b == '\r' {
				if next, e := s.reader.Peek(1); e == nil && next[0] == '\n' {
					s.reader.ReadByte()
					raw.WriteByte('\n')
				}
			}
			if lineBytes == 0 {
				return raw.Bytes(), nil
			}
			lineBytes = 0
		} else {
			lineBytes++
		}
	}
}
func sseData(record []byte) (string, string) {
	text := strings.ReplaceAll(strings.ReplaceAll(string(record), "\r\n", "\n"), "\r", "\n")
	var data []string
	event := ""
	for _, line := range strings.Split(text, "\n") {
		if line == "data" {
			data = append(data, "")
		} else if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(line[5:], " "))
		} else if strings.HasPrefix(line, "event:") {
			event = strings.TrimPrefix(line[6:], " ")
		}
	}
	return strings.Join(data, "\n"), event
}
func (s *sseReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for len(s.pending) == 0 {
		if s.ended {
			return 0, io.EOF
		}
		record, e := s.record()
		if e != nil {
			s.ended = true
			if e == io.EOF && s.finish != nil {
				e = s.finish()
				if e == nil {
					e = io.EOF
				}
			}
			return 0, e
		}
		data, _ := sseData(record)
		if data == "[DONE]" { // Authenticate trailing OHTTP frames before exposing completion.
			if _, e = io.Copy(io.Discard, s.reader); e == nil && s.finish != nil {
				e = s.finish()
			}
			s.ended = true
			if e != nil {
				return 0, e
			}
		}
		if s.transform != nil {
			record, e = s.transform(record)
			if e != nil {
				s.ended = true
				return 0, e
			}
		}
		s.pending = record
	}
	n := copy(p, s.pending)
	s.pending = s.pending[n:]
	return n, nil
}
func (s *sseReader) Close() error {
	var e error
	s.closeOnce.Do(func() { e = s.source.Close() })
	return e
}
func (p *PreparedE2EEChatRequest) transformSSE(record []byte) ([]byte, error) {
	data, event := sseData(record)
	if data == "" || data == "[DONE]" || event == "error" {
		return record, nil
	}
	body, e := decodeObject([]byte(data))
	if e != nil {
		return nil, e
	}
	if _, ok := body["choices"]; !ok {
		return record, nil
	}
	if e = decryptChat(body, p.key, true); e != nil {
		return nil, e
	}
	encoded, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	// Preserve controls and each original line ending. Place the transformed JSON
	// in the final data line so mixed CR/LF cannot consume the record boundary.
	type line struct{ text, ending string }
	var lines []line
	raw := string(record)
	last := -1
	for len(raw) > 0 {
		idx := strings.IndexAny(raw, "\r\n")
		if idx < 0 {
			lines = append(lines, line{raw, ""})
			raw = ""
		} else {
			end := idx + 1
			if raw[idx] == '\r' && end < len(raw) && raw[end] == '\n' {
				end++
			}
			lines = append(lines, line{raw[:idx], raw[idx:end]})
			raw = raw[end:]
		}
		t := lines[len(lines)-1].text
		if t == "data" || strings.HasPrefix(t, "data:") {
			last = len(lines) - 1
		}
	}
	var out strings.Builder
	for i, l := range lines {
		if l.text == "data" || strings.HasPrefix(l.text, "data:") {
			if i == last {
				out.WriteString("data: ")
				out.Write(encoded)
				out.WriteString(l.ending)
			}
		} else {
			out.WriteString(l.text)
			out.WriteString(l.ending)
		}
	}
	return []byte(out.String()), nil
}

// DecryptSSE streams protocol fields while retaining SSE controls. It owns source.
func (p *PreparedE2EEChatRequest) DecryptSSE(source io.ReadCloser) io.ReadCloser {
	return &sseReader{source: source, reader: bufio.NewReader(source), transform: p.transformSSE, limit: 64 << 20}
}

type captureReader struct {
	io.ReadCloser
	body  bytes.Buffer
	limit int64
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, e := c.ReadCloser.Read(p)
	if int64(c.body.Len()+n) > c.limit {
		return 0, failure("api.body_too_large", nil)
	}
	c.body.Write(p[:n])
	return n, e
}
