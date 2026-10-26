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
pub(crate) fn transform(
    record: &[u8],
    key: Option<&ResponseKey>,
    id: &mut Option<String>,
    responses: bool,
    messages: bool,
) -> Result<Vec<u8>, InferenceError> {
    let text = std::str::from_utf8(record).map_err(|_| invalid_response())?;
    let lines = lines(text);
    let values: Vec<_> = lines.iter().filter_map(|(line, _)| data(line)).collect();
    let joined = values.join("\n");
    if values.is_empty()
        || joined.is_empty()
        || joined == "[DONE]"
        || event_name(&lines) == Some("error")
    {
        return Ok(record.to_vec());
    }
    let mut body: Value = match serde_json::from_str(&joined) {
        Ok(value) => value,
        Err(_) if key.is_none() => return Ok(record.to_vec()),
        Err(_) => return Err(invalid_response().into()),
    };
    // Responses lifecycle events nest the receipt ID; item IDs are unrelated.
    let receipt = if responses {
        &body["response"]
    } else if messages {
        if body["type"] == "message_start" {
            &body["message"]
        } else {
            &Value::Null
        }
    } else {
        &body
    };
    if let Some(value) = receipt
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        if id.as_ref().is_some_and(|s| s != value) {
            return Err(invalid_response().into());
        }
        *id = Some(value.to_owned());
    }
    let Some(key) = key else {
        return Ok(record.to_vec());
    };
    if !body.is_object() {
        return Err(invalid_response().into());
    }
    if body.get("choices").is_none() {
        return Ok(record.to_vec());
    }
    decrypt_response(&mut body, key, true)?;
    let mut result = String::new();
    let mut remaining = values.len();
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
    Ok(result.into_bytes())
}

#[derive(Default)]
pub(crate) struct MessageStreamState {
    started: bool,
    stopped: bool,
}

impl MessageStreamState {
    pub(crate) fn observe(&mut self, record: &[u8]) -> Result<(), InferenceError> {
        let text = std::str::from_utf8(record).map_err(|_| invalid_response())?;
        let lines = lines(text);
        if !lines.last().is_some_and(|(line, _)| line.is_empty()) {
            return Err(invalid_response().into());
        }
        let joined = lines
            .iter()
            .filter_map(|(line, _)| data(line))
            .collect::<Vec<_>>()
            .join("\n");
        let name = event_name(&lines);
        if name == Some("error") {
            return Err(invalid_response().into());
        }
        if joined.is_empty() {
            return Ok(());
        }
        let event: Value = serde_json::from_str(&joined).map_err(|_| invalid_response())?;
        let kind = event["type"].as_str();
        if self.stopped
            || kind == Some("error")
            || kind.is_none_or(str::is_empty)
            || name.is_some_and(|name| Some(name) != kind)
        {
            return Err(invalid_response().into());
        }
        match kind {
            Some("message_start") => {
                if self.started {
                    return Err(invalid_response().into());
                }
                self.started = true;
            }
            Some("message_stop") => self.stopped = true,
            _ => {}
        }
        Ok(())
    }
    pub(crate) fn finish(&self) -> Result<(), InferenceError> {
        if !self.started || !self.stopped {
            return Err(invalid_response().into());
        }
        Ok(())
    }
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
