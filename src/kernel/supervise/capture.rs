//! What a relay keeps of a child's stream for the sandbox failure
//! classifier.

/// What a relay keeps of a stream for the classifier: its first `limit`
/// bytes, and, when it ran past them, `\n...\n` and its real last line,
/// from a window of its last `limit` bytes kept alongside. A check on the
/// last line then judges the whole stream, not where the head stopped. A
/// last line longer than the window is kept as `...` alone.
pub(crate) struct Capture {
    limit: usize,
    head: Vec<u8>,
    window: Vec<u8>,
    overflowed: bool,
}

impl Capture {
    pub(crate) fn new(limit: usize) -> Self {
        Self {
            limit,
            head: Vec::new(),
            window: Vec::new(),
            overflowed: false,
        }
    }

    pub(crate) fn push(&mut self, bytes: &[u8]) {
        if self.limit == 0 {
            return;
        }
        let room = self.limit.saturating_sub(self.head.len()).min(bytes.len());
        self.head.extend_from_slice(&bytes[..room]);
        self.overflowed |= room < bytes.len();
        self.window.extend_from_slice(bytes);
        let over = self.window.len().saturating_sub(self.limit);
        self.window.drain(..over);
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        let mut kept = self.head;
        if self.overflowed {
            let window = self.window.strip_suffix(b"\n").unwrap_or(&self.window);
            kept.extend_from_slice(b"\n...");
            if let Some(start) = window.iter().rposition(|byte| *byte == b'\n') {
                kept.push(b'\n');
                kept.extend_from_slice(&window[start + 1..]);
            }
        }
        kept
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A capture keeps the head of the stream and, once the stream ran past
    /// it, the stream's real last line, wherever the reads split it.
    #[test]
    fn a_capture_keeps_the_head_and_the_real_last_line() {
        let capture = |chunks: &[&[u8]]| {
            let mut capture = Capture::new(8);
            chunks.iter().for_each(|chunk| capture.push(chunk));
            capture.finish()
        };
        assert_eq!(capture(&[b"short\n"]), b"short\n");
        assert_eq!(capture(&[b"exactly\n"]), b"exactly\n");
        assert_eq!(
            capture(&[b"head of", b" it\nla", b"st\n"]),
            b"head of \n...\nlast"
        );
        assert_eq!(
            capture(&[b"head\nlast\n", b"tail"]),
            b"head\nlas\n...\ntail"
        );
        assert_eq!(
            capture(&[b"one line far past the window"]),
            b"one line\n..."
        );
        assert_eq!(Capture::new(0).finish(), b"");
        let mut nothing = Capture::new(0);
        nothing.push(b"stdout");
        assert_eq!(nothing.finish(), b"");
    }
}
