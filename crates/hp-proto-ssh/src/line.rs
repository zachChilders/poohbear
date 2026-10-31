//! Minimal terminal line discipline for an interactive shell channel.
//!
//! A real sshd hands the shell a pty, and the *tty* does local echo and line
//! editing. We have no pty, so this does just enough of that to feel right:
//! echo, backspace, Ctrl-C, Ctrl-D, and swallowing escape sequences (arrow
//! keys) so they don't end up in the command. It is a pure state machine so
//! it can be tested without any network.

/// Longest line we keep; further bytes are dropped (a real tty also caps).
const MAX_LINE: usize = 4096;

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Edit {
    /// Bytes to send back to the peer as local echo.
    Echo(Vec<u8>),
    /// A completed line (without the terminator).
    Line(Vec<u8>),
    /// Ctrl-C: the line was discarded.
    Interrupt,
    /// Ctrl-D on an empty line: end of input.
    Eof,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Escape {
    None,
    /// Saw ESC.
    Esc,
    /// Inside a CSI/SS3 sequence; ends at a byte in 0x40..=0x7e.
    Csi,
}

pub(crate) struct LineEditor {
    echo: bool,
    buf: Vec<u8>,
    escape: Escape,
    /// The previous byte was CR, so an immediately following LF is part of
    /// the same line ending.
    after_cr: bool,
}

impl LineEditor {
    /// `echo` is true for pty sessions; piped (non-pty) input is not echoed.
    pub(crate) fn new(echo: bool) -> LineEditor {
        LineEditor {
            echo,
            buf: Vec::new(),
            escape: Escape::None,
            after_cr: false,
        }
    }

    pub(crate) fn feed(&mut self, data: &[u8]) -> Vec<Edit> {
        let mut out = Vec::new();
        for &b in data {
            let after_cr = std::mem::take(&mut self.after_cr);
            match self.escape {
                Escape::Esc => {
                    self.escape = if b == b'[' || b == b'O' {
                        Escape::Csi
                    } else {
                        Escape::None
                    };
                    continue;
                }
                Escape::Csi => {
                    if (0x40..=0x7e).contains(&b) {
                        self.escape = Escape::None;
                    }
                    continue;
                }
                Escape::None => {}
            }
            match b {
                0x1b => self.escape = Escape::Esc,
                b'\r' | b'\n' => {
                    if b == b'\n' && after_cr {
                        continue;
                    }
                    self.after_cr = b == b'\r';
                    self.echo(&mut out, b"\r\n");
                    out.push(Edit::Line(std::mem::take(&mut self.buf)));
                }
                0x7f | 0x08 => {
                    if self.pop_char() {
                        self.echo(&mut out, b"\x08 \x08");
                    }
                }
                0x03 => {
                    self.buf.clear();
                    self.echo(&mut out, b"^C\r\n");
                    out.push(Edit::Interrupt);
                }
                0x04 => {
                    if self.buf.is_empty() {
                        out.push(Edit::Eof);
                    }
                }
                // Other control bytes (tab, Ctrl-U, ...) are ignored.
                0x00..=0x1f => {}
                _ => {
                    if self.buf.len() < MAX_LINE {
                        self.buf.push(b);
                        self.echo(&mut out, &[b]);
                    }
                }
            }
        }
        out
    }

    /// Remove the last character (a whole UTF-8 sequence). False if empty.
    fn pop_char(&mut self) -> bool {
        if self.buf.is_empty() {
            return false;
        }
        while let Some(b) = self.buf.pop() {
            if b & 0xC0 != 0x80 {
                break;
            }
        }
        true
    }

    /// Queue echo, merging with a preceding echo to keep writes few.
    fn echo(&self, out: &mut Vec<Edit>, bytes: &[u8]) {
        if !self.echo {
            return;
        }
        match out.last_mut() {
            Some(Edit::Echo(prev)) => prev.extend_from_slice(bytes),
            _ => out.push(Edit::Echo(bytes.to_vec())),
        }
    }
}

/// Translate bare `\n` to `\r\n`, as a tty's output processing (ONLCR) does.
/// Tracks output are written with plain `\n`.
pub(crate) fn to_crlf(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 8);
    let mut prev = 0u8;
    for &b in data {
        if b == b'\n' && prev != b'\r' {
            out.push(b'\r');
        }
        out.push(b);
        prev = b;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed(ed: &mut LineEditor, s: &[u8]) -> Vec<Edit> {
        ed.feed(s)
    }
    fn echo(s: &[u8]) -> Edit {
        Edit::Echo(s.to_vec())
    }
    fn line(s: &[u8]) -> Edit {
        Edit::Line(s.to_vec())
    }

    #[test]
    fn typing_echoes_and_enter_submits() {
        let mut ed = LineEditor::new(true);
        assert_eq!(feed(&mut ed, b"ls"), [echo(b"ls")]);
        assert_eq!(feed(&mut ed, b"\r"), [echo(b"\r\n"), line(b"ls")]);
    }

    #[test]
    fn echo_is_coalesced_with_the_newline_in_one_chunk() {
        let mut ed = LineEditor::new(true);
        assert_eq!(feed(&mut ed, b"id\r"), [echo(b"id\r\n"), line(b"id")]);
    }

    #[test]
    fn piped_input_is_not_echoed() {
        let mut ed = LineEditor::new(false);
        assert_eq!(feed(&mut ed, b"a\nb\n"), [line(b"a"), line(b"b")]);
    }

    #[test]
    fn crlf_is_one_line_ending_not_two() {
        let mut ed = LineEditor::new(false);
        assert_eq!(feed(&mut ed, b"a\r\nb\r"), [line(b"a"), line(b"b")]);
        // ...even when split across reads
        assert_eq!(feed(&mut ed, b"\nc\n"), [line(b"c")]);
    }

    #[test]
    fn blank_lines_are_submitted() {
        let mut ed = LineEditor::new(false);
        assert_eq!(feed(&mut ed, b"\n\n"), [line(b""), line(b"")]);
    }

    #[test]
    fn backspace_erases_one_character_and_echoes_the_erase() {
        let mut ed = LineEditor::new(true);
        feed(&mut ed, b"lsx");
        assert_eq!(feed(&mut ed, b"\x7f"), [echo(b"\x08 \x08")]);
        assert_eq!(feed(&mut ed, b"\r"), [echo(b"\r\n"), line(b"ls")]);
        assert!(
            feed(&mut ed, b"\x7f\x08").is_empty(),
            "nothing to erase on an empty line"
        );
    }

    #[test]
    fn backspace_removes_a_whole_utf8_character() {
        let mut ed = LineEditor::new(false);
        feed(&mut ed, "aé".as_bytes());
        feed(&mut ed, b"\x7f");
        assert_eq!(feed(&mut ed, b"\n"), [line(b"a")]);
    }

    #[test]
    fn ctrl_c_discards_the_line() {
        let mut ed = LineEditor::new(true);
        feed(&mut ed, b"rm -rf");
        assert_eq!(feed(&mut ed, b"\x03"), [echo(b"^C\r\n"), Edit::Interrupt]);
        assert_eq!(feed(&mut ed, b"\n"), [echo(b"\r\n"), line(b"")]);
    }

    #[test]
    fn ctrl_d_ends_input_only_on_an_empty_line() {
        let mut ed = LineEditor::new(true);
        feed(&mut ed, b"x");
        assert!(feed(&mut ed, b"\x04").is_empty());
        feed(&mut ed, b"\x7f");
        assert_eq!(feed(&mut ed, b"\x04"), [Edit::Eof]);
    }

    #[test]
    fn escape_sequences_are_swallowed_even_when_split_across_reads() {
        let mut ed = LineEditor::new(false);
        assert!(feed(&mut ed, b"\x1b[").is_empty());
        assert!(feed(&mut ed, b"1;5A").is_empty());
        assert!(feed(&mut ed, b"\x1bOA\x1bx").is_empty());
        assert_eq!(feed(&mut ed, b"ok\n"), [line(b"ok")]);
    }

    #[test]
    fn other_control_bytes_are_ignored() {
        let mut ed = LineEditor::new(false);
        assert_eq!(feed(&mut ed, b"a\tb\x15\x00c\n"), [line(b"abc")]);
    }

    #[test]
    fn lines_are_capped() {
        let mut ed = LineEditor::new(false);
        let mut input = vec![b'a'; MAX_LINE + 100];
        input.push(b'\n');
        let Edit::Line(l) = &ed.feed(&input)[0] else {
            panic!("no line")
        };
        assert_eq!(l.len(), MAX_LINE);
    }

    #[test]
    fn crlf_translation() {
        assert_eq!(to_crlf(b"a\nb\r\nc\n\n"), b"a\r\nb\r\nc\r\n\r\n");
        assert_eq!(to_crlf(b""), b"");
        assert_eq!(to_crlf(b"no newline"), b"no newline");
    }
}
