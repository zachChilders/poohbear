//! Parsing a shell command line.
//!
//! Covers what attackers actually type: quoting, `$VAR` and `~` expansion,
//! `;` `&&` `||` `|` `&`, and redirects (`>` `>>` `<` `2>` `2>&1` `&>`).
//! Deliberately *not* supported: `$(...)`, backticks, subshells, here-docs,
//! loops. They are left as literal text, and a real shell would also not do
//! anything dangerous with them here since nothing is ever executed.
//!
//! Parsing is pure: variables are looked up through a callback, and nothing
//! touches a filesystem.

/// Most tokens and commands a single line may contain.
const MAX_TOKENS: usize = 512;
const MAX_ITEMS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Word {
    pub text: String,
    /// Contained an unquoted `*`, `?` or `[`, so it should be glob-expanded.
    pub glob: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Join {
    /// `;` (or the first command)
    Seq,
    /// `&&`
    And,
    /// `||`
    Or,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Redir {
    File { path: Word, append: bool },
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Command {
    pub words: Vec<Word>,
    pub stdin: Option<Word>,
    pub stdout: Option<Redir>,
    pub stderr: Option<Redir>,
    /// `2>&1`
    pub stderr_to_stdout: bool,
    /// `>&2`
    pub stdout_to_stderr: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Pipeline {
    pub commands: Vec<Command>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Script {
    pub items: Vec<(Join, Pipeline)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    /// An opened quote was never closed.
    Unterminated(char),
    /// Misplaced operator; carries the token bash would name.
    Syntax(String),
    TooComplex,
}

impl ParseError {
    /// The text bash would print.
    pub fn message(&self) -> String {
        match self {
            ParseError::Unterminated(q) => {
                format!("unexpected EOF while looking for matching `{q}'")
            }
            ParseError::Syntax(t) => format!("syntax error near unexpected token `{t}'"),
            ParseError::TooComplex => "command line too complex".into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Word(Word),
    Semi,
    And,
    Or,
    Pipe,
    /// `&` (background): treated like `;`, nothing runs in the background here.
    Amp,
    /// `>` / `>>` with the fd they apply to: 1, 2, or 0 meaning both (`&>`).
    Out {
        fd: u8,
        append: bool,
    },
    In,
    /// `2>&1`
    ErrToOut,
    /// `>&2`
    OutToErr,
}

fn is_name_start(c: char) -> bool {
    c.is_ascii_alphabetic() || c == '_'
}

/// Expand `$NAME`, `${NAME}` and `$?` starting just after a `$`. Returns the
/// expansion and how many chars were consumed, or None for a literal `$`.
fn expand_var(rest: &[char], vars: &dyn Fn(&str) -> Option<String>) -> Option<(String, usize)> {
    match rest.first()? {
        '?' => Some((vars("?").unwrap_or_default(), 1)),
        '{' => {
            let end = rest.iter().position(|&c| c == '}')?;
            let name: String = rest[1..end].iter().collect();
            if name.is_empty() || !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
                return None;
            }
            Some((vars(&name).unwrap_or_default(), end + 1))
        }
        &c if is_name_start(c) => {
            let len = rest
                .iter()
                .take_while(|c| c.is_ascii_alphanumeric() || **c == '_')
                .count();
            let name: String = rest[..len].iter().collect();
            Some((vars(&name).unwrap_or_default(), len))
        }
        _ => None,
    }
}

#[allow(unused_assignments)] // the final flush resets state nobody reads
fn lex(
    line: &str,
    vars: &dyn Fn(&str) -> Option<String>,
    home: &str,
) -> Result<Vec<Tok>, ParseError> {
    let cs: Vec<char> = line.chars().collect();
    let mut toks = Vec::new();
    let mut cur = String::new();
    let mut in_word = false;
    let mut glob = false;
    // Saw a quote in this word, so an empty result is a real empty argument
    // (`""`), not the nothing an unset unquoted `$VAR` leaves behind.
    let mut quoted = false;
    let mut i = 0;

    macro_rules! flush {
        () => {
            if in_word && (quoted || !cur.is_empty()) {
                toks.push(Tok::Word(Word {
                    text: std::mem::take(&mut cur),
                    glob,
                }));
            }
            cur.clear();
            in_word = false;
            glob = false;
            quoted = false;
        };
    }

    while i < cs.len() {
        if toks.len() > MAX_TOKENS {
            return Err(ParseError::TooComplex);
        }
        let c = cs[i];
        match c {
            c if c.is_whitespace() => {
                flush!();
                i += 1;
            }
            '\'' => {
                let end = cs[i + 1..]
                    .iter()
                    .position(|&x| x == '\'')
                    .ok_or(ParseError::Unterminated('\''))?;
                cur.extend(&cs[i + 1..i + 1 + end]);
                in_word = true;
                quoted = true;
                i += end + 2;
            }
            '"' => {
                in_word = true;
                quoted = true;
                i += 1;
                loop {
                    let d = *cs.get(i).ok_or(ParseError::Unterminated('"'))?;
                    i += 1;
                    match d {
                        '"' => break,
                        '\\' => match cs.get(i) {
                            Some(&e @ ('"' | '\\' | '$' | '`')) => {
                                cur.push(e);
                                i += 1;
                            }
                            _ => cur.push('\\'),
                        },
                        '$' => match expand_var(&cs[i..], vars) {
                            Some((v, used)) => {
                                cur.push_str(&v);
                                i += used;
                            }
                            None => cur.push('$'),
                        },
                        other => cur.push(other),
                    }
                }
            }
            '\\' => {
                if let Some(&n) = cs.get(i + 1) {
                    if n != '\n' {
                        cur.push(n);
                        in_word = true;
                    }
                }
                i += 2;
            }
            '$' => match expand_var(&cs[i + 1..], vars) {
                Some((v, used)) => {
                    // Unquoted expansions are split on whitespace, as in a shell.
                    for (n, piece) in v.split_whitespace().enumerate() {
                        if n > 0 {
                            flush!();
                        }
                        cur.push_str(piece);
                        in_word = true;
                    }
                    i += used + 1;
                }
                None => {
                    cur.push('$');
                    in_word = true;
                    i += 1;
                }
            },
            '~' if !in_word && cs.get(i + 1).is_none_or(|n| *n == '/' || n.is_whitespace()) => {
                cur.push_str(home);
                in_word = true;
                i += 1;
            }
            '#' if !in_word => break,
            '*' | '?' | '[' => {
                glob = true;
                cur.push(c);
                in_word = true;
                i += 1;
            }
            ';' => {
                flush!();
                toks.push(Tok::Semi);
                i += 1;
            }
            '|' => {
                flush!();
                if cs.get(i + 1) == Some(&'|') {
                    toks.push(Tok::Or);
                    i += 2;
                } else {
                    toks.push(Tok::Pipe);
                    i += 1;
                }
            }
            '&' => {
                if cs.get(i + 1) == Some(&'&') {
                    flush!();
                    toks.push(Tok::And);
                    i += 2;
                } else if cs.get(i + 1) == Some(&'>') {
                    flush!();
                    let append = cs.get(i + 2) == Some(&'>');
                    toks.push(Tok::Out { fd: 0, append });
                    i += if append { 3 } else { 2 };
                } else {
                    flush!();
                    toks.push(Tok::Amp);
                    i += 1;
                }
            }
            '<' => {
                flush!();
                toks.push(Tok::In);
                i += 1;
            }
            '>' => {
                // An unquoted lone `1` or `2` just before `>` names the fd.
                let fd = if in_word && !glob && (cur == "1" || cur == "2") {
                    let fd = if cur == "2" { 2 } else { 1 };
                    cur.clear();
                    in_word = false;
                    fd
                } else {
                    flush!();
                    1
                };
                if cs.get(i + 1) == Some(&'&') && matches!(cs.get(i + 2), Some('1' | '2')) {
                    toks.push(if cs[i + 2] == '1' && fd == 2 {
                        Tok::ErrToOut
                    } else {
                        Tok::OutToErr
                    });
                    i += 3;
                    continue;
                }
                let append = cs.get(i + 1) == Some(&'>');
                toks.push(Tok::Out { fd, append });
                i += if append { 2 } else { 1 };
            }
            other => {
                cur.push(other);
                in_word = true;
                i += 1;
            }
        }
    }
    flush!();
    Ok(toks)
}

/// Split a line into the pieces a shell runs one after another, at `;`, `&&`,
/// `||` and `&` outside quotes. Each piece is paired with how it joins the
/// previous one. A shell expands `$VAR` and `$?` when it reaches a command, so
/// callers parse and run these one at a time (`false; echo $?` must print 1).
///
/// Pipelines stay whole, and redirect operators that contain a `&`
/// (`2>&1`, `&>file`) are not separators.
pub fn segments(line: &str) -> Vec<(Join, String)> {
    let cs: Vec<char> = line.chars().collect();
    let (mut out, mut cur) = (Vec::new(), String::new());
    let mut join = Join::Seq;
    let (mut i, mut quote) = (0, None::<char>);
    while i < cs.len() {
        let c = cs[i];
        if let Some(q) = quote {
            cur.push(c);
            if c == '\\' && q == '"' && i + 1 < cs.len() {
                cur.push(cs[i + 1]);
                i += 1;
            } else if c == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        let next = cs.get(i + 1).copied();
        let prev = cur.chars().last();
        let sep = match c {
            '\\' => {
                cur.push(c);
                if let Some(n) = next {
                    cur.push(n);
                    i += 1;
                }
                i += 1;
                continue;
            }
            '\'' | '"' => {
                quote = Some(c);
                cur.push(c);
                i += 1;
                continue;
            }
            // a comment runs to the end of the line, but `a#b` is a word
            '#' if prev.is_none_or(char::is_whitespace) => break,
            ';' => Some((Join::Seq, 1)),
            '&' if next == Some('&') => Some((Join::And, 2)),
            '|' if next == Some('|') => Some((Join::Or, 2)),
            '&' if next != Some('>') && !matches!(prev, Some('>' | '<')) => Some((Join::Seq, 1)),
            _ => None,
        };
        match sep {
            Some((next_join, width)) => {
                out.push((join, std::mem::take(&mut cur)));
                join = next_join;
                i += width;
            }
            None => {
                cur.push(c);
                i += 1;
            }
        }
    }
    out.push((join, cur));
    out
}

/// Parse `line` into a script. `vars` resolves `$NAME`; `home` is `~`.
pub fn parse(
    line: &str,
    vars: &dyn Fn(&str) -> Option<String>,
    home: &str,
) -> Result<Script, ParseError> {
    let toks = lex(line, vars, home)?;
    let mut script = Script::default();
    let mut pipeline = Pipeline::default();
    let mut cmd = Command::default();
    let mut join = Join::Seq;
    let mut it = toks.into_iter().peekable();

    let syntax = |t: &str| ParseError::Syntax(t.to_string());
    // The target of a redirect must be a word.
    let take_word = |it: &mut std::iter::Peekable<std::vec::IntoIter<Tok>>| match it.next() {
        Some(Tok::Word(w)) => Ok(w),
        Some(other) => Err(syntax(&tok_text(&other))),
        None => Err(syntax("newline")),
    };

    while let Some(tok) = it.next() {
        match tok {
            Tok::Word(w) => cmd.words.push(w),
            Tok::Out { fd, append } => {
                let path = take_word(&mut it)?;
                let r = Redir::File { path, append };
                match fd {
                    2 => cmd.stderr = Some(r),
                    0 => {
                        // `&>file`: stdout to the file, stderr merged into it
                        cmd.stdout = Some(r);
                        cmd.stderr_to_stdout = true;
                    }
                    _ => cmd.stdout = Some(r),
                }
            }
            Tok::In => cmd.stdin = Some(take_word(&mut it)?),
            Tok::ErrToOut => cmd.stderr_to_stdout = true,
            Tok::OutToErr => cmd.stdout_to_stderr = true,
            Tok::Pipe => {
                if cmd.words.is_empty() {
                    return Err(syntax("|"));
                }
                pipeline.commands.push(std::mem::take(&mut cmd));
            }
            Tok::Semi | Tok::Amp | Tok::And | Tok::Or => {
                let next_join = match tok {
                    Tok::And => Join::And,
                    Tok::Or => Join::Or,
                    _ => Join::Seq,
                };
                // An operator needs a command before it (`;;`, a leading `;`
                // and `| |` are errors); a bare redirect (`> file`) counts.
                if !present(&cmd) {
                    return Err(syntax(&tok_text(&tok)));
                }
                pipeline.commands.push(std::mem::take(&mut cmd));
                script.items.push((join, std::mem::take(&mut pipeline)));
                join = next_join;
                if script.items.len() > MAX_ITEMS {
                    return Err(ParseError::TooComplex);
                }
                // `&&` / `||` need a command after them
                if matches!(next_join, Join::And | Join::Or) && it.peek().is_none() {
                    return Err(syntax("newline"));
                }
            }
        }
    }
    if present(&cmd) {
        // (`> file` alone is a command that creates/truncates the file.)
        pipeline.commands.push(cmd);
        script.items.push((join, pipeline));
    } else if !pipeline.commands.is_empty() {
        return Err(syntax("newline")); // a trailing `|`
    }
    Ok(script)
}

/// Does this command have anything to run: words, or at least a redirect?
fn present(c: &Command) -> bool {
    !c.words.is_empty() || c.stdout.is_some() || c.stderr.is_some() || c.stdin.is_some()
}

fn tok_text(t: &Tok) -> String {
    match t {
        Tok::Semi => ";".into(),
        Tok::And => "&&".into(),
        Tok::Or => "||".into(),
        Tok::Pipe => "|".into(),
        Tok::Amp => "&".into(),
        Tok::Out { append: true, .. } => ">>".into(),
        Tok::Out { .. } => ">".into(),
        Tok::In => "<".into(),
        Tok::ErrToOut | Tok::OutToErr => ">&".into(),
        Tok::Word(w) => w.text.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(name: &str) -> Option<String> {
        match name {
            "HOME" => Some("/home/admin".into()),
            "X" => Some("hello world".into()),
            "?" => Some("0".into()),
            _ => None,
        }
    }
    fn p(line: &str) -> Result<Script, ParseError> {
        parse(line, &vars, "/home/admin")
    }
    fn words(line: &str) -> Vec<String> {
        p(line).unwrap().items[0].1.commands[0]
            .words
            .iter()
            .map(|w| w.text.clone())
            .collect()
    }

    #[test]
    fn splits_words_and_handles_quotes_and_escapes() {
        assert_eq!(words("echo a  b"), ["echo", "a", "b"]);
        assert_eq!(
            words("echo 'a  b' \"c d\" e\\ f"),
            ["echo", "a  b", "c d", "e f"]
        );
        assert_eq!(
            words(r#"echo "a \"q\" \$X \\ \n""#),
            ["echo", r#"a "q" $X \ \n"#]
        );
        assert_eq!(
            words("echo ''"),
            ["echo", ""],
            "an empty quoted word still counts"
        );
        assert_eq!(
            words("echo a'b'\"c\""),
            ["echo", "abc"],
            "adjacent quoting joins"
        );
    }

    #[test]
    fn expands_variables_with_shell_word_splitting() {
        assert_eq!(
            words("echo $HOME ${HOME}x end"),
            ["echo", "/home/admin", "/home/adminx", "end"]
        );
        assert_eq!(
            words("echo \"$X\" '$X'"),
            ["echo", "hello world", "$X"],
            "quotes keep one word"
        );
        assert_eq!(
            words("echo $X"),
            ["echo", "hello", "world"],
            "unquoted expansion splits"
        );
        assert_eq!(words("echo a$NOPE b"), ["echo", "a", "b"]);
        assert_eq!(
            words("echo $NOPE end"),
            ["echo", "end"],
            "an unset unquoted variable vanishes"
        );
        assert_eq!(
            words("echo \"$NOPE\" end"),
            ["echo", "", "end"],
            "...but quoted it is an empty argument"
        );
        assert_eq!(words("echo $?"), ["echo", "0"]);
        assert_eq!(
            words("echo $ ${} $1 $-"),
            ["echo", "$", "${}", "$1", "$-"],
            "unsupported forms stay literal"
        );
    }

    #[test]
    fn tilde_expands_only_at_the_start_of_a_word() {
        let s = p("cd ~ ; echo ~/x a~b ~root").unwrap();
        assert_eq!(s.items[0].1.commands[0].words[1].text, "/home/admin");
        let echo: Vec<_> = s.items[1].1.commands[0]
            .words
            .iter()
            .map(|w| w.text.as_str())
            .collect();
        assert_eq!(echo, ["echo", "/home/admin/x", "a~b", "~root"]);
    }

    #[test]
    fn operators_chain_commands() {
        let s = p("a ; b && c || d").unwrap();
        let joins: Vec<_> = s.items.iter().map(|(j, _)| *j).collect();
        assert_eq!(joins, [Join::Seq, Join::Seq, Join::And, Join::Or]);
        let s = p("a | b | c").unwrap();
        assert_eq!(s.items.len(), 1);
        assert_eq!(s.items[0].1.commands.len(), 3);
        assert_eq!(p("a &").unwrap().items.len(), 1, "background is accepted");
        assert_eq!(p("a;").unwrap().items.len(), 1, "trailing ; is fine");
        assert_eq!(p("").unwrap().items.len(), 0);
        assert_eq!(p("   # just a comment").unwrap().items.len(), 0);
        assert_eq!(words("echo hi # trailing comment"), ["echo", "hi"]);
        assert_eq!(
            words("echo a#b"),
            ["echo", "a#b"],
            "# inside a word is literal"
        );
    }

    #[test]
    fn redirects() {
        let c = &p("cat < in > out").unwrap().items[0].1.commands[0];
        assert_eq!(c.stdin.as_ref().unwrap().text, "in");
        assert!(
            matches!(&c.stdout, Some(Redir::File { path, append: false }) if path.text == "out")
        );
        let c = &p("echo x >> log 2> err").unwrap().items[0].1.commands[0];
        assert!(matches!(&c.stdout, Some(Redir::File { append: true, .. })));
        assert!(matches!(&c.stderr, Some(Redir::File { path, .. }) if path.text == "err"));
        let c = &p("x >/dev/null 2>&1").unwrap().items[0].1.commands[0];
        assert!(c.stderr_to_stdout && c.stdout.is_some());
        let c = &p("x >&2").unwrap().items[0].1.commands[0];
        assert!(c.stdout_to_stderr);
        let c = &p("x &>/dev/null").unwrap().items[0].1.commands[0];
        assert!(c.stdout.is_some() && c.stderr_to_stdout);
        let c = &p("echo 1>out").unwrap().items[0].1.commands[0];
        assert_eq!(c.words.len(), 1, "`1>` names the fd, it is not an argument");
        let c = &p("echo 12>out").unwrap().items[0].1.commands[0];
        assert_eq!(c.words.len(), 2, "`12>` is an argument and stdout");
    }

    #[test]
    fn segments_split_at_connectors_outside_quotes() {
        let seg = |l: &str| -> Vec<(Join, String)> { segments(l) };
        assert_eq!(
            seg("a ; b && c || d"),
            [
                (Join::Seq, "a ".into()),
                (Join::Seq, " b ".into()),
                (Join::And, " c ".into()),
                (Join::Or, " d".into())
            ]
        );
        assert_eq!(seg("a | b").len(), 1, "a pipeline is one segment");
        assert_eq!(
            seg("echo 'a; b' \"c && d\"").len(),
            1,
            "quotes protect connectors"
        );
        assert_eq!(seg("echo a\\;b").len(), 1, "an escaped ; is literal");
        assert_eq!(
            seg("x 2>&1 ; y").len(),
            2,
            "2>&1 is a redirect, not a separator"
        );
        assert_eq!(seg("x &>/dev/null").len(), 1);
        assert_eq!(seg("x >&2").len(), 1);
        assert_eq!(seg("sleep 1 & echo hi").len(), 2, "a lone & separates");
        assert_eq!(seg("echo a # b ; c").len(), 1, "comments end the line");
        assert_eq!(seg("echo a#b ; c").len(), 2, "# inside a word is literal");
        assert_eq!(seg("").len(), 1);
    }

    #[test]
    fn a_lone_redirect_is_a_command_that_truncates() {
        let s = p("> file").unwrap();
        assert_eq!(s.items.len(), 1);
        assert!(s.items[0].1.commands[0].words.is_empty());
    }

    #[test]
    fn globs_are_marked_only_when_unquoted() {
        let w = &p("ls *.txt '*.md' a?").unwrap().items[0].1.commands[0].words;
        assert!(w[1].glob && !w[2].glob && w[3].glob);
    }

    #[test]
    fn errors_name_the_offending_token_like_bash() {
        assert_eq!(p("echo 'x").unwrap_err(), ParseError::Unterminated('\''));
        assert_eq!(p("echo \"x").unwrap_err(), ParseError::Unterminated('"'));
        assert_eq!(p("; ls").unwrap_err(), ParseError::Syntax(";".into()));
        assert_eq!(p("ls ;; ls").unwrap_err(), ParseError::Syntax(";".into()));
        assert_eq!(p("| ls").unwrap_err(), ParseError::Syntax("|".into()));
        assert_eq!(p("ls |").unwrap_err(), ParseError::Syntax("newline".into()));
        assert_eq!(
            p("ls &&").unwrap_err(),
            ParseError::Syntax("newline".into())
        );
        assert_eq!(p("ls >").unwrap_err(), ParseError::Syntax("newline".into()));
        assert_eq!(p("ls > ;").unwrap_err(), ParseError::Syntax(";".into()));
        assert!(p("ls ;;")
            .unwrap_err()
            .message()
            .contains("syntax error near unexpected token"));
        assert!(p("'").unwrap_err().message().contains("matching"));
        assert_eq!(ParseError::TooComplex.message(), "command line too complex");
    }

    #[test]
    fn pathological_lines_are_bounded() {
        let many = "a;".repeat(MAX_ITEMS + 10);
        assert_eq!(p(&many).unwrap_err(), ParseError::TooComplex);
        let toks = "a ".repeat(MAX_TOKENS + 10);
        assert_eq!(p(&toks).unwrap_err(), ParseError::TooComplex);
        assert!(
            p(&"(".repeat(10_000)).is_ok(),
            "parens are literal text, not nesting"
        );
    }

    #[test]
    fn unsupported_constructs_stay_literal() {
        assert_eq!(words("echo $(id) `id`"), ["echo", "$(id)", "`id`"]);
    }
}
