//! The deliberately tiny expression language: integer/string/bool literals,
//! variables, arithmetic, comparisons, `&& || !`, and a fixed set of helpers.
//! No loops, no assignment, no user-defined functions.

use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Int(i64),
    Str(String),
    Bool(bool),
}

impl Value {
    pub fn type_name(&self) -> &'static str {
        match self {
            Value::Int(_) => "int",
            Value::Str(_) => "string",
            Value::Bool(_) => "bool",
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Value::Int(n) => write!(f, "{n}"),
            Value::Str(s) => f.write_str(s),
            Value::Bool(b) => write!(f, "{b}"),
        }
    }
}

/// Variable lookup used during evaluation.
pub type Env<'a> = &'a dyn Fn(&str) -> Option<Value>;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BinOp { Add, Sub, Mul, Div, Rem, Eq, Ne, Lt, Le, Gt, Ge, And, Or }

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum UnOp { Not, Neg }

#[derive(Debug, Clone)]
pub enum Expr {
    Lit(Value),
    Var(String),
    Unary(UnOp, Box<Expr>),
    Bin(BinOp, Box<Expr>, Box<Expr>),
    Call(String, Vec<Expr>),
}

// ---------------------------------------------------------------- lexing

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Int(i64),
    Str(String),
    Ident(String),
    Op(&'static str),
    LParen,
    RParen,
    Comma,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let cs: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < cs.len() {
        let c = cs[i];
        if c.is_whitespace() {
            i += 1;
        } else if c.is_ascii_digit() {
            let s = i;
            while i < cs.len() && cs[i].is_ascii_digit() { i += 1; }
            let t: String = cs[s..i].iter().collect();
            out.push(Tok::Int(t.parse().map_err(|_| format!("integer literal {t} is too large"))?));
        } else if c.is_ascii_alphabetic() || c == '_' {
            let s = i;
            while i < cs.len() && (cs[i].is_ascii_alphanumeric() || cs[i] == '_') { i += 1; }
            out.push(Tok::Ident(cs[s..i].iter().collect()));
        } else if c == '\'' || c == '"' {
            i += 1;
            let mut s = String::new();
            loop {
                let d = *cs.get(i).ok_or("unterminated string literal")?;
                i += 1;
                if d == c { break; }
                if d == '\\' {
                    let e = *cs.get(i).ok_or("unterminated string literal")?;
                    i += 1;
                    s.push(match e { 'n' => '\n', 't' => '\t', 'r' => '\r', o => o });
                } else {
                    s.push(d);
                }
            }
            out.push(Tok::Str(s));
        } else {
            let two: String = cs[i..(i + 2).min(cs.len())].iter().collect();
            if let Some(o) = ["==", "!=", "<=", ">=", "&&", "||"].into_iter().find(|o| *o == two) {
                out.push(Tok::Op(o));
                i += 2;
                continue;
            }
            out.push(match c {
                '+' => Tok::Op("+"), '-' => Tok::Op("-"), '*' => Tok::Op("*"),
                '/' => Tok::Op("/"), '%' => Tok::Op("%"), '<' => Tok::Op("<"),
                '>' => Tok::Op(">"), '!' => Tok::Op("!"),
                '(' => Tok::LParen, ')' => Tok::RParen, ',' => Tok::Comma,
                other => return Err(format!("unexpected character {other:?}")),
            });
            i += 1;
        }
    }
    Ok(out)
}

// --------------------------------------------------------------- parsing

fn binop(o: &str) -> Option<(BinOp, u8)> {
    Some(match o {
        "||" => (BinOp::Or, 1),
        "&&" => (BinOp::And, 2),
        "==" => (BinOp::Eq, 3), "!=" => (BinOp::Ne, 3),
        "<" => (BinOp::Lt, 4), "<=" => (BinOp::Le, 4), ">" => (BinOp::Gt, 4), ">=" => (BinOp::Ge, 4),
        "+" => (BinOp::Add, 5), "-" => (BinOp::Sub, 5),
        "*" => (BinOp::Mul, 6), "/" => (BinOp::Div, 6), "%" => (BinOp::Rem, 6),
        _ => return None,
    })
}

struct Parser { t: Vec<Tok>, i: usize }

/// Maximum nesting depth, so hostile-ish track files can't overflow the stack.
const MAX_DEPTH: usize = 64;

impl Parser {
    fn peek(&self) -> Option<&Tok> { self.t.get(self.i) }

    fn expr(&mut self, min: u8, depth: usize) -> Result<Expr, String> {
        if depth > MAX_DEPTH { return Err("expression nested too deeply".into()); }
        let mut lhs = self.unary(depth)?;
        loop {
            let (op, prec) = match self.peek() {
                Some(Tok::Op(o)) => match binop(o) { Some(x) => x, None => break },
                _ => break,
            };
            if prec < min { break; }
            self.i += 1;
            let rhs = self.expr(prec + 1, depth + 1)?;
            lhs = Expr::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn unary(&mut self, depth: usize) -> Result<Expr, String> {
        if depth > MAX_DEPTH { return Err("expression nested too deeply".into()); }
        let op = match self.peek() {
            Some(Tok::Op("!")) => Some(UnOp::Not),
            Some(Tok::Op("-")) => Some(UnOp::Neg),
            _ => None,
        };
        if let Some(op) = op {
            self.i += 1;
            return Ok(Expr::Unary(op, Box::new(self.unary(depth + 1)?)));
        }
        self.primary(depth)
    }

    fn primary(&mut self, depth: usize) -> Result<Expr, String> {
        let tok = self.t.get(self.i).cloned();
        self.i += 1;
        match tok {
            Some(Tok::Int(n)) => Ok(Expr::Lit(Value::Int(n))),
            Some(Tok::Str(s)) => Ok(Expr::Lit(Value::Str(s))),
            Some(Tok::LParen) => {
                let e = self.expr(0, depth + 1)?;
                match self.t.get(self.i) {
                    Some(Tok::RParen) => { self.i += 1; Ok(e) }
                    _ => Err("expected `)`".into()),
                }
            }
            Some(Tok::Ident(name)) => {
                if name == "true" { return Ok(Expr::Lit(Value::Bool(true))); }
                if name == "false" { return Ok(Expr::Lit(Value::Bool(false))); }
                if !matches!(self.peek(), Some(Tok::LParen)) { return Ok(Expr::Var(name)); }
                self.i += 1;
                let mut args = Vec::new();
                if matches!(self.peek(), Some(Tok::RParen)) {
                    self.i += 1;
                    return Ok(Expr::Call(name, args));
                }
                loop {
                    args.push(self.expr(0, depth + 1)?);
                    match self.t.get(self.i) {
                        Some(Tok::Comma) => self.i += 1,
                        Some(Tok::RParen) => { self.i += 1; break; }
                        _ => return Err(format!("expected `,` or `)` in call to {name}")),
                    }
                }
                Ok(Expr::Call(name, args))
            }
            Some(t) => Err(format!("unexpected token {t:?}")),
            None => Err("unexpected end of expression".into()),
        }
    }
}

pub fn parse(src: &str) -> Result<Expr, String> {
    let mut p = Parser { t: lex(src)?, i: 0 };
    let e = p.expr(0, 0)?;
    if p.i < p.t.len() { return Err(format!("unexpected trailing token {:?}", p.t[p.i])); }
    Ok(e)
}

// ------------------------------------------------------------ validation

pub fn arity(name: &str) -> Option<usize> {
    match name {
        "basename" | "dirname" | "len" | "lower" | "upper" | "str" | "int" => Some(1),
        "contains" => Some(2),
        _ => None,
    }
}

impl Expr {
    /// Static checks: unknown identifiers, unknown functions, wrong arity.
    pub fn check(&self, known: &dyn Fn(&str) -> bool, errs: &mut Vec<String>) {
        match self {
            Expr::Lit(_) => {}
            Expr::Var(v) => if !known(v) { errs.push(format!("unknown variable `{v}`")); },
            Expr::Unary(_, e) => e.check(known, errs),
            Expr::Bin(_, a, b) => { a.check(known, errs); b.check(known, errs); }
            Expr::Call(name, args) => {
                match arity(name) {
                    None => errs.push(format!("unknown function `{name}`")),
                    Some(n) if n != args.len() =>
                        errs.push(format!("`{name}` takes {n} argument(s), got {}", args.len())),
                    _ => {}
                }
                for a in args { a.check(known, errs); }
            }
        }
    }

    pub fn eval(&self, env: Env) -> Result<Value, String> {
        match self {
            Expr::Lit(v) => Ok(v.clone()),
            Expr::Var(n) => env(n).ok_or_else(|| format!("unbound variable `{n}`")),
            Expr::Unary(op, e) => match (op, e.eval(env)?) {
                (UnOp::Not, Value::Bool(b)) => Ok(Value::Bool(!b)),
                (UnOp::Neg, Value::Int(n)) => n.checked_neg().map(Value::Int).ok_or_else(|| "integer overflow".into()),
                (_, v) => Err(format!("cannot apply unary operator to {}", v.type_name())),
            },
            Expr::Bin(BinOp::And, a, b) => match a.eval(env)? {
                Value::Bool(false) => Ok(Value::Bool(false)),
                Value::Bool(true) => expect_bool(b.eval(env)?),
                v => Err(format!("`&&` needs bool, got {}", v.type_name())),
            },
            Expr::Bin(BinOp::Or, a, b) => match a.eval(env)? {
                Value::Bool(true) => Ok(Value::Bool(true)),
                Value::Bool(false) => expect_bool(b.eval(env)?),
                v => Err(format!("`||` needs bool, got {}", v.type_name())),
            },
            Expr::Bin(op, a, b) => binary(*op, a.eval(env)?, b.eval(env)?),
            Expr::Call(name, args) => {
                let vals = args.iter().map(|a| a.eval(env)).collect::<Result<Vec<_>, _>>()?;
                call(name, &vals)
            }
        }
    }
}

fn expect_bool(v: Value) -> Result<Value, String> {
    match v { Value::Bool(_) => Ok(v), o => Err(format!("expected bool, got {}", o.type_name())) }
}

fn binary(op: BinOp, a: Value, b: Value) -> Result<Value, String> {
    use BinOp::*;
    use Value::*;
    let overflow = || "integer overflow or division by zero".to_string();
    match (op, a, b) {
        (Add, Int(x), Int(y)) => x.checked_add(y).map(Int).ok_or_else(overflow),
        (Add, Str(x), Str(y)) => Ok(Str(x + &y)),
        (Sub, Int(x), Int(y)) => x.checked_sub(y).map(Int).ok_or_else(overflow),
        (Mul, Int(x), Int(y)) => x.checked_mul(y).map(Int).ok_or_else(overflow),
        (Div, Int(x), Int(y)) => x.checked_div(y).map(Int).ok_or_else(overflow),
        (Rem, Int(x), Int(y)) => x.checked_rem(y).map(Int).ok_or_else(overflow),
        (Eq, x, y) if x.type_name() == y.type_name() => Ok(Bool(x == y)),
        (Ne, x, y) if x.type_name() == y.type_name() => Ok(Bool(x != y)),
        (Lt, Int(x), Int(y)) => Ok(Bool(x < y)),
        (Le, Int(x), Int(y)) => Ok(Bool(x <= y)),
        (Gt, Int(x), Int(y)) => Ok(Bool(x > y)),
        (Ge, Int(x), Int(y)) => Ok(Bool(x >= y)),
        (Lt, Str(x), Str(y)) => Ok(Bool(x < y)),
        (Le, Str(x), Str(y)) => Ok(Bool(x <= y)),
        (Gt, Str(x), Str(y)) => Ok(Bool(x > y)),
        (Ge, Str(x), Str(y)) => Ok(Bool(x >= y)),
        (op, x, y) => Err(format!("cannot apply {op:?} to {} and {}", x.type_name(), y.type_name())),
    }
}

fn string_arg<'a>(f: &str, v: &'a Value) -> Result<&'a str, String> {
    match v { Value::Str(s) => Ok(s), o => Err(format!("`{f}` needs a string, got {}", o.type_name())) }
}

fn call(name: &str, a: &[Value]) -> Result<Value, String> {
    match name {
        "basename" => Ok(Value::Str(string_arg(name, &a[0])?.trim_end_matches('/').rsplit('/').next().unwrap_or("").to_string())),
        "dirname" => {
            let s = string_arg(name, &a[0])?.trim_end_matches('/');
            Ok(Value::Str(match s.rfind('/') {
                None => ".".into(),
                Some(0) => "/".into(),
                Some(i) => s[..i].to_string(),
            }))
        }
        "len" => Ok(Value::Int(string_arg(name, &a[0])?.chars().count() as i64)),
        "lower" => Ok(Value::Str(string_arg(name, &a[0])?.to_lowercase())),
        "upper" => Ok(Value::Str(string_arg(name, &a[0])?.to_uppercase())),
        "str" => Ok(Value::Str(a[0].to_string())),
        "int" => string_arg(name, &a[0])?.trim().parse().map(Value::Int).map_err(|_| "int(): not an integer".to_string()),
        "contains" => Ok(Value::Bool(string_arg(name, &a[0])?.contains(string_arg(name, &a[1])?))),
        _ => Err(format!("unknown function `{name}`")),
    }
}

// -------------------------------------------------------------- templates

/// A string with `${expr}` interpolations.
#[derive(Debug, Clone)]
pub struct Template(Vec<Part>);

#[derive(Debug, Clone)]
enum Part { Lit(String), Expr(Expr) }

pub fn is_template(src: &str) -> bool { src.contains("${") }

impl Template {
    pub fn parse(src: &str) -> Result<Template, String> {
        let mut parts = Vec::new();
        let mut rest = src;
        while let Some(start) = rest.find("${") {
            if start > 0 { parts.push(Part::Lit(rest[..start].to_string())); }
            let body = &rest[start + 2..];
            let end = find_close(body).ok_or("unterminated `${`")?;
            parts.push(Part::Expr(parse(&body[..end])?));
            rest = &body[end + 1..];
        }
        if !rest.is_empty() { parts.push(Part::Lit(rest.to_string())); }
        Ok(Template(parts))
    }

    pub fn check(&self, known: &dyn Fn(&str) -> bool, errs: &mut Vec<String>) {
        for p in &self.0 { if let Part::Expr(e) = p { e.check(known, errs); } }
    }

    pub fn render(&self, env: Env) -> Result<String, String> {
        let mut out = String::new();
        for p in &self.0 {
            match p {
                Part::Lit(s) => out.push_str(s),
                Part::Expr(e) => out.push_str(&e.eval(env)?.to_string()),
            }
        }
        Ok(out)
    }
}

/// Index of the `}` closing an interpolation, skipping quoted strings.
fn find_close(s: &str) -> Option<usize> {
    let mut quote: Option<char> = None;
    let mut esc = false;
    for (i, c) in s.char_indices() {
        match quote {
            Some(q) => {
                if esc { esc = false } else if c == '\\' { esc = true } else if c == q { quote = None }
            }
            None => match c {
                '\'' | '"' => quote = Some(c),
                '}' => return Some(i),
                _ => {}
            },
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(src: &str) -> Result<Value, String> {
        let env = |n: &str| match n {
            "n" => Some(Value::Int(2)),
            "s" => Some(Value::Str("/a/b.sh".into())),
            _ => None,
        };
        parse(src)?.eval(&env)
    }

    #[test]
    fn arithmetic_and_precedence() {
        assert_eq!(ev("1 + 2 * 3"), Ok(Value::Int(7)));
        assert_eq!(ev("(1 + 2) * 3"), Ok(Value::Int(9)));
        assert_eq!(ev("n + 1"), Ok(Value::Int(3)));
        assert_eq!(ev("-n + 5"), Ok(Value::Int(3)));
        assert_eq!(ev("7 % 4"), Ok(Value::Int(3)));
    }

    #[test]
    fn comparisons_and_logic() {
        assert_eq!(ev("n < 3 && n >= 2"), Ok(Value::Bool(true)));
        assert_eq!(ev("!(n == 2) || false"), Ok(Value::Bool(false)));
        assert_eq!(ev("s == '/a/b.sh'"), Ok(Value::Bool(true)));
    }

    #[test]
    fn short_circuit_skips_errors() {
        assert_eq!(ev("false && (1 / 0 == 1)"), Ok(Value::Bool(false)));
        assert_eq!(ev("true || (1 / 0 == 1)"), Ok(Value::Bool(true)));
    }

    #[test]
    fn helpers() {
        assert_eq!(ev("basename(s)"), Ok(Value::Str("b.sh".into())));
        assert_eq!(ev("dirname(s)"), Ok(Value::Str("/a".into())));
        assert_eq!(ev("upper('ab') + str(n)"), Ok(Value::Str("AB2".into())));
        assert_eq!(ev("int('42') + len('abc')"), Ok(Value::Int(45)));
        assert_eq!(ev("contains(s, 'b.')"), Ok(Value::Bool(true)));
    }

    #[test]
    fn errors_not_panics() {
        assert!(ev("1 / 0").is_err());
        assert!(ev("9223372036854775807 + 1").is_err());
        assert!(ev("1 + 'a'").is_err());
        assert!(ev("1 == 'a'").is_err());
        assert!(ev("nope").is_err());
        assert!(ev("1 +").is_err());
        assert!(ev("(1").is_err());
        assert!(ev("1 2").is_err());
        assert!(ev("'abc").is_err());
        assert!(ev("99999999999999999999").is_err());
    }

    #[test]
    fn deep_nesting_is_rejected() {
        let src = "(".repeat(10_000) + "1" + &")".repeat(10_000);
        assert!(parse(&src).is_err());
        assert!(parse(&"-".repeat(10_000)).is_err());
    }

    #[test]
    fn templates() {
        let env = |n: &str| (n == "u").then(|| Value::Str("http://x/y.sh".into()));
        let t = Template::parse("got ${basename(u)} (${len('}')})").unwrap();
        assert_eq!(t.render(&env).unwrap(), "got y.sh (1)");
        assert!(Template::parse("oops ${u").is_err());
        assert!(Template::parse("${1 +}").is_err());
    }

    #[test]
    fn static_check() {
        let known = |n: &str| n == "a";
        let mut errs = vec![];
        parse("a + b + nope(1) + len(1, 2)").unwrap().check(&known, &mut errs);
        assert_eq!(errs.len(), 3, "{errs:?}");
    }
}
