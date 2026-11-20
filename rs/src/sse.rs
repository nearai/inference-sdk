use crate::{
    e2ee::{decrypt_response, invalid_response, ResponseKey},
    InferenceError,
};
use serde_json::Value;

/// Incremental scanner: never rescan an unfinished line.
#[derive(Default)]
pub(crate) struct SseDecoder {
    pending: Vec<u8>,
    scan: usize,
    line: usize,
}
impl SseDecoder {
    pub(crate) fn push(&mut self, bytes: &[u8], eof: bool) -> Vec<Vec<u8>> {
        let mut records = Vec::new();
        for part in bytes.chunks(8192) {
            self.pending.extend_from_slice(part);
            self.scan_records(false, &mut records);
        }
        if eof {
            self.scan_records(true, &mut records);
            if !self.pending.is_empty() {
                records.push(std::mem::take(&mut self.pending));
            }
            self.scan = 0;
            self.line = 0;
        }
        records
    }
    fn scan_records(&mut self, eof: bool, records: &mut Vec<Vec<u8>>) {
        let mut start = 0;
        while self.scan < self.pending.len() {
            let i = self.scan;
            let byte = self.pending[i];
            if byte != b'\r' && byte != b'\n' {
                self.scan += 1;
                continue;
            }
            if byte == b'\r' && i + 1 == self.pending.len() && !eof {
                break;
            }
            let end = i + if byte == b'\r' && self.pending.get(i + 1) == Some(&b'\n') {
                2
            } else {
                1
            };
            if i == self.line {
                records.push(self.pending[start..end].to_vec());
                start = end;
            }
            self.line = end;
            self.scan = end;
        }
        self.pending.drain(..start);
        self.scan -= start;
        self.line -= start;
    }
}
fn lines(record: &str) -> Vec<(&str, &str)> {
    let bytes = record.as_bytes();
    let mut result = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'\r' && bytes[i] != b'\n' {
            i += 1;
            continue;
        }
        let end = i + if bytes[i] == b'\r' && bytes.get(i + 1) == Some(&b'\n') {
            2
        } else {
            1
        };
        result.push((&record[start..i], &record[i..end]));
        start = end;
        i = end;
    }
    if start < record.len() {
        result.push((&record[start..], ""));
    }
    result
}
fn data(line: &str) -> Option<&str> {
    if line == "data" {
        Some("")
    } else {
        line.strip_prefix("data:")
            .map(|s| s.strip_prefix(' ').unwrap_or(s))
    }
}
fn event_name<'a>(lines: &[(&'a str, &str)]) -> Option<&'a str> {
    lines
        .iter()
        .filter_map(|(line, _)| {
            if *line == "event" {
                Some("")
            } else {
                line.strip_prefix("event:")
                    .map(|name| name.strip_prefix(' ').unwrap_or(name))
            }
        })
        .next_back()
}
#[derive(Clone, Copy, PartialEq)]
pub(crate) enum SseMode {
    DecryptOnly,
    Chat,
    Responses,
    Messages,
}

pub(crate) struct SseStream {
    mode: SseMode,
    first: bool,
    done: bool,
    id: Option<String>,
    message_stopped: bool,
}

impl SseStream {
    pub(crate) fn new(mode: SseMode) -> Self {
        Self {
            mode,
            first: true,
            done: false,
            id: None,
            message_stopped: false,
        }
    }

    pub(crate) fn transform(
        &mut self,
        record: Vec<u8>,
        key: Option<&ResponseKey>,
    ) -> Result<Vec<u8>, InferenceError> {
        if self.done {
            return Ok(record);
        }
        let parsed = if std::mem::take(&mut self.first) {
            record.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&record)
        } else {
            &record
        };
        let text = std::str::from_utf8(parsed).map_err(|_| invalid_response())?;
        let lines = lines(text);
        let event = event_name(&lines);
        let values: Vec<_> = lines.iter().filter_map(|(line, _)| data(line)).collect();
        let joined = values.join("\n");
        if self.mode == SseMode::Messages && !lines.last().is_some_and(|(line, _)| line.is_empty())
        {
            return Err(invalid_response().into());
        }
        if event == Some("error") && self.mode != SseMode::DecryptOnly {
            return Err(invalid_response().into());
        }
        if joined == "[DONE]" {
            if self.mode == SseMode::Messages
                || (self.mode != SseMode::DecryptOnly && self.id.is_none())
            {
                return Err(invalid_response().into());
            }
            self.done = true;
        } else if !joined.is_empty() && event != Some("error") {
            let mut body: Value = serde_json::from_str(&joined).map_err(|_| invalid_response())?;
            if !body.is_object() {
                return Err(invalid_response().into());
            }
            self.observe(event, &body)?;
            if let Some(key) = key.filter(|_| body.get("choices").is_some()) {
                decrypt_response(&mut body, key, true)?;
                return Ok(replace_data(lines, values.len(), &body));
            }
        }
        // Preserve the wire representation on plaintext transports.
        Ok(if key.is_some() && parsed.len() != record.len() {
            parsed.to_vec()
        } else {
            record
        })
    }

    fn observe(&mut self, event: Option<&str>, body: &Value) -> Result<(), InferenceError> {
        let receipt = match self.mode {
            SseMode::DecryptOnly => return Ok(()),
            SseMode::Messages => {
                let kind = body["type"].as_str();
                if self.message_stopped
                    || kind.is_none_or(str::is_empty)
                    || kind == Some("error")
                    || event.is_some_and(|name| Some(name) != kind)
                {
                    return Err(invalid_response().into());
                }
                if kind == Some("message_stop") {
                    self.message_stopped = true;
                }
                if kind != Some("message_start") {
                    return Ok(());
                }
                if self.id.is_some() {
                    return Err(invalid_response().into());
                }
                &body["message"]
            }
            SseMode::Chat | SseMode::Responses => {
                if body.get("error").is_some() || body["type"] == "error" {
                    return Err(invalid_response().into());
                }
                if self.mode == SseMode::Chat {
                    if body.get("id").is_none() {
                        return Ok(());
                    }
                    body
                } else {
                    // Output item IDs are unrelated to the Responses receipt.
                    let Some(response) = body.get("response") else {
                        return Ok(());
                    };
                    response
                }
            }
        };
        let id = receipt["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .ok_or_else(invalid_response)?;
        if let Some(previous) = self.id.as_deref() {
            if previous != id {
                return Err(invalid_response().into());
            }
        } else {
            self.id = Some(id.to_owned());
        }
        Ok(())
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.done || self.message_stopped
    }

    pub(crate) fn finish(self) -> Result<String, InferenceError> {
        if self.mode == SseMode::Messages && !self.message_stopped {
            return Err(invalid_response().into());
        }
        Ok(self.id.ok_or_else(invalid_response)?)
    }
}

fn replace_data(lines: Vec<(&str, &str)>, mut remaining: usize, body: &Value) -> Vec<u8> {
    let mut result = String::new();
    for (line, ending) in lines {
        if data(line).is_none() {
            result.push_str(line);
            result.push_str(ending);
        } else {
            remaining -= 1;
            if remaining == 0 {
                result.push_str("data: ");
                result.push_str(&body.to_string());
                result.push_str(ending);
            }
        }
    }
    result.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_split_preserves_records_and_utf8() {
        let records = [
            "data: 🌍\r\n\r\n",
            ": heartbeat\r\r",
            "data: [DONE]\n\n",
            ": tail",
        ];
        let input = records.concat().into_bytes();
        for split in 0..=input.len() {
            let mut decoder = SseDecoder::default();
            let mut got = decoder.push(&input[..split], false);
            got.extend(decoder.push(&input[split..], true));
            assert_eq!(
                got,
                records
                    .iter()
                    .map(|r| r.as_bytes().to_vec())
                    .collect::<Vec<_>>()
            );
        }
    }
    #[test]
    fn large_records_preserve_payload_across_chunks() {
        let input = format!("data: {}\n\n", "x".repeat(1024 * 1024 + 1));
        let mut decoder = SseDecoder::default();
        let mut records = Vec::new();
        for chunk in input.as_bytes().chunks(17) {
            records.extend(decoder.push(chunk, false));
        }
        records.extend(decoder.push(&[], true));
        assert_eq!(records, vec![input.into_bytes()]);
    }
}
