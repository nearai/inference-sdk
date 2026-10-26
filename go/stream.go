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
	terminal  func([]byte) bool
	finish    func() error
	pending   []byte
	ended     bool
	closeOnce sync.Once
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
	data, event, _ := sseFields(record)
	return data, event
}

func sseFields(record []byte) (string, string, bool) {
	text := strings.ReplaceAll(strings.ReplaceAll(string(record), "\r\n", "\n"), "\r", "\n")
	var data []string
	event := ""
	hasEvent := false
	for _, line := range strings.Split(text, "\n") {
		if line == "data" {
			data = append(data, "")
		} else if strings.HasPrefix(line, "data:") {
			data = append(data, strings.TrimPrefix(line[5:], " "))
		} else if line == "event" {
			event, hasEvent = "", true
		} else if strings.HasPrefix(line, "event:") {
			event, hasEvent = strings.TrimPrefix(line[6:], " "), true
		}
	}
	return strings.Join(data, "\n"), event, hasEvent
}

func completeSSERecord(record []byte) bool {
	text := strings.ReplaceAll(strings.ReplaceAll(string(record), "\r\n", "\n"), "\r", "\n")
	return strings.HasSuffix(text, "\n\n")
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
		if s.transform != nil {
			record, e = s.transform(record)
			if e != nil {
				s.ended = true
				return 0, e
			}
		}
		if s.terminal != nil && s.terminal(record) {
			// Messages clients may stop reading at message_stop. Validate all
			// remaining records and OHTTP frames before exposing that event.
			for {
				tail, err := s.record()
				if err == io.EOF {
					break
				}
				if err != nil {
					s.ended = true
					return 0, err
				}
				if s.transform != nil {
					tail, err = s.transform(tail)
					if err != nil {
						s.ended = true
						return 0, err
					}
				}
				record = append(record, tail...)
			}
			s.ended = true
			if s.finish != nil {
				if err := s.finish(); err != nil {
					return 0, err
				}
			}
		} else if data == "[DONE]" {
			// Authenticate trailing OHTTP frames before exposing completion.
			if _, e = io.Copy(io.Discard, s.reader); e == nil && s.finish != nil {
				e = s.finish()
			}
			s.ended = true
			if e != nil {
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
	return &sseReader{source: source, reader: bufio.NewReader(source), transform: p.transformSSE}
}

type captureReader struct {
	io.ReadCloser
	body bytes.Buffer
}

func (c *captureReader) Read(p []byte) (int, error) {
	n, e := c.ReadCloser.Read(p)
	c.body.Write(p[:n])
	return n, e
}
