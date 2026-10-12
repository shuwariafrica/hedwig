//! The subset of JSON the model is written in, parsed strictly.
//!
//! Every number is an integer, every object key is unique, nesting is bounded,
//! and one text holds one value. A control client is a wire peer, so the
//! parser is total: every input yields a value or a [`JsonError`] naming the
//! byte, and none makes it recurse past [`DEPTH`].

use std::fmt;

/// The deepest nesting accepted. The deepest message the protocol defines
/// nests to a third of this.
pub const DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Json {
    Null,
    Bool(bool),
    /// An integer from `i64::MIN` to `u64::MAX`.
    Number(i128),
    Text(String),
    List(Vec<Json>),
    /// Keys in the order written.
    Map(Vec<(String, Json)>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flaw {
    /// The text ended inside a value.
    End,
    /// A byte that cannot start or continue what is being read.
    Unexpected,
    /// Nested deeper than [`DEPTH`].
    Depth,
    /// A number with a fraction, an exponent or a leading zero, or outside
    /// `i64::MIN..=u64::MAX`.
    Number,
    /// An escape that is not one of JSON's, or a surrogate without its pair.
    Escape,
    /// A control character written raw inside a string.
    Control,
    /// A key that an object already holds.
    DuplicateKey,
    /// Something after the one value.
    Trailing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JsonError {
    /// The byte offset at which reading stopped.
    pub at: usize,
    pub flaw: Flaw,
}

impl fmt::Display for JsonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.flaw {
            Flaw::End => "the text ends inside a value",
            Flaw::Unexpected => "an unexpected character",
            Flaw::Depth => "nested too deeply",
            Flaw::Number => "a number that is not a plain integer in range",
            Flaw::Escape => "an invalid escape in a string",
            Flaw::Control => "a raw control character in a string",
            Flaw::DuplicateKey => "a key given twice",
            Flaw::Trailing => "something follows the value",
        };
        write!(f, "{what} at byte {}", self.at)
    }
}

impl std::error::Error for JsonError {}

/// Parses one value, with nothing but whitespace around it.
///
/// # Errors
///
/// A [`JsonError`] naming the first byte that does not belong.
pub fn parse(text: &str) -> Result<Json, JsonError> {
    let mut reader = Reader { text, at: 0 };
    let value = reader.value(0)?;
    reader.blank();
    if reader.at == text.len() {
        Ok(value)
    } else {
        Err(reader.flawed(Flaw::Trailing))
    }
}

struct Reader<'a> {
    text: &'a str,
    at: usize,
}

impl Reader<'_> {
    fn flawed(&self, flaw: Flaw) -> JsonError {
        JsonError { at: self.at, flaw }
    }

    fn peek(&self) -> Option<u8> {
        self.text.as_bytes().get(self.at).copied()
    }

    fn blank(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn expect(&mut self, literal: &str) -> Result<(), JsonError> {
        let rest = self.text.get(self.at..).unwrap_or_default();
        if rest.starts_with(literal) {
            self.at += literal.len();
            Ok(())
        } else if literal.starts_with(rest) {
            self.at = self.text.len();
            Err(self.flawed(Flaw::End))
        } else {
            Err(self.flawed(Flaw::Unexpected))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.blank();
        match self.peek() {
            None => Err(self.flawed(Flaw::End)),
            Some(b'n') => self.expect("null").map(|()| Json::Null),
            Some(b't') => self.expect("true").map(|()| Json::Bool(true)),
            Some(b'f') => self.expect("false").map(|()| Json::Bool(false)),
            Some(b'"') => self.string().map(Json::Text),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(b'[' | b'{') if depth == DEPTH => Err(self.flawed(Flaw::Depth)),
            Some(b'[') => self.list(depth + 1),
            Some(b'{') => self.map(depth + 1),
            Some(_) => Err(self.flawed(Flaw::Unexpected)),
        }
    }

    fn list(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.at += 1;
        let mut items = Vec::new();
        self.blank();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Json::List(items));
        }
        loop {
            items.push(self.value(depth)?);
            self.blank();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Json::List(items));
                }
                Some(_) => return Err(self.flawed(Flaw::Unexpected)),
                None => return Err(self.flawed(Flaw::End)),
            }
        }
    }

    fn map(&mut self, depth: usize) -> Result<Json, JsonError> {
        self.at += 1;
        let mut members: Vec<(String, Json)> = Vec::new();
        self.blank();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Json::Map(members));
        }
        loop {
            self.blank();
            let key_at = self.at;
            let key = match self.peek() {
                Some(b'"') => self.string()?,
                Some(_) => return Err(self.flawed(Flaw::Unexpected)),
                None => return Err(self.flawed(Flaw::End)),
            };
            if members.iter().any(|(known, _)| *known == key) {
                return Err(JsonError {
                    at: key_at,
                    flaw: Flaw::DuplicateKey,
                });
            }
            self.blank();
            match self.peek() {
                Some(b':') => self.at += 1,
                Some(_) => return Err(self.flawed(Flaw::Unexpected)),
                None => return Err(self.flawed(Flaw::End)),
            }
            let value = self.value(depth)?;
            members.push((key, value));
            self.blank();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Json::Map(members));
                }
                Some(_) => return Err(self.flawed(Flaw::Unexpected)),
                None => return Err(self.flawed(Flaw::End)),
            }
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.at;
        let negative = self.peek() == Some(b'-');
        if negative {
            self.at += 1;
        }
        let digits_at = self.at;
        let mut magnitude: i128 = 0;
        while let Some(digit @ b'0'..=b'9') = self.peek() {
            magnitude = magnitude * 10 + i128::from(digit - b'0');
            self.at += 1;
            // Twenty digits hold `u64::MAX`; a twenty-first cannot be in range.
            if self.at - digits_at > 20 {
                return Err(JsonError {
                    at: start,
                    flaw: Flaw::Number,
                });
            }
        }
        let digits = self.text.get(digits_at..self.at).unwrap_or_default();
        let plain = !digits.is_empty()
            && (digits == "0" || !digits.starts_with('0'))
            && !matches!(self.peek(), Some(b'.' | b'e' | b'E'));
        let value = if negative { -magnitude } else { magnitude };
        if plain && value >= i128::from(i64::MIN) && value <= i128::from(u64::MAX) {
            Ok(Json::Number(value))
        } else {
            Err(JsonError {
                at: start,
                flaw: Flaw::Number,
            })
        }
    }

    /// The bytes from here to the quote that closes the string, which is never
    /// fewer than the string decodes to.
    fn span(&self) -> usize {
        let bytes = self.text.as_bytes();
        let mut end = self.at;
        loop {
            match bytes.get(end) {
                None | Some(b'"') => return end.min(bytes.len()) - self.at,
                Some(b'\\') => end += 2,
                Some(_) => end += 1,
            }
        }
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.at += 1;
        // Sized once and never grown: a string can be the person's passphrase,
        // and growing would leave a copy of what was read so far behind.
        let mut out = String::with_capacity(self.span());
        loop {
            let run = self.at;
            while !matches!(self.peek(), None | Some(b'"' | b'\\' | 0..=0x1f)) {
                self.at += 1;
            }
            out.push_str(self.text.get(run..self.at).unwrap_or_default());
            match self.peek() {
                None => return Err(self.flawed(Flaw::End)),
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => out.push(self.escape()?),
                Some(_) => return Err(self.flawed(Flaw::Control)),
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let at = self.at;
        let flawed = JsonError {
            at,
            flaw: Flaw::Escape,
        };
        self.at += 1;
        let escaped = self.peek().ok_or(JsonError {
            at: self.text.len(),
            flaw: Flaw::End,
        })?;
        self.at += 1;
        Ok(match escaped {
            b'"' => '"',
            b'\\' => '\\',
            b'/' => '/',
            b'b' => '\u{8}',
            b'f' => '\u{c}',
            b'n' => '\n',
            b'r' => '\r',
            b't' => '\t',
            b'u' => {
                let high = self.hex4().ok_or(flawed)?;
                let scalar = if (0xd800..0xdc00).contains(&high) {
                    self.expect("\\u").map_err(|_| flawed)?;
                    let low = self.hex4().ok_or(flawed)?;
                    if !(0xdc00..0xe000).contains(&low) {
                        return Err(flawed);
                    }
                    0x1_0000 + ((high - 0xd800) << 10) + (low - 0xdc00)
                } else {
                    high
                };
                char::from_u32(scalar).ok_or(flawed)?
            }
            _ => return Err(flawed),
        })
    }

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.text.get(self.at..self.at + 4)?;
        if !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        self.at += 4;
        u32::from_str_radix(digits, 16).ok()
    }
}

/// How a value is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    /// One line with no whitespace: a frame on the control channel, an entry
    /// of the trail. It never contains a line feed, which is what lets a line
    /// be a frame.
    Line,
    /// Indented, one member per line: a configuration document a person
    /// reads and compares.
    Page,
}

/// Renders a value. The same value always renders to the same bytes.
pub fn render(json: &Json, layout: Layout) -> String {
    let mut out = String::new();
    write(json, layout, 0, &mut out);
    if layout == Layout::Page {
        out.push('\n');
    }
    out
}

fn write(json: &Json, layout: Layout, depth: usize, out: &mut String) {
    match json {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Number(number) => out.push_str(&number.to_string()),
        Json::Text(text) => quote(text, out),
        Json::List(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                separate(index, layout, depth + 1, out);
                write(item, layout, depth + 1, out);
            }
            close(items.is_empty(), layout, depth, out);
            out.push(']');
        }
        Json::Map(members) => {
            out.push('{');
            for (index, (key, value)) in members.iter().enumerate() {
                separate(index, layout, depth + 1, out);
                quote(key, out);
                out.push_str(if layout == Layout::Page { ": " } else { ":" });
                write(value, layout, depth + 1, out);
            }
            close(members.is_empty(), layout, depth, out);
            out.push('}');
        }
    }
}

fn separate(index: usize, layout: Layout, depth: usize, out: &mut String) {
    if index > 0 {
        out.push(',');
    }
    if layout == Layout::Page {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    }
}

fn close(empty: bool, layout: Layout, depth: usize, out: &mut String) {
    if !empty && layout == Layout::Page {
        out.push('\n');
        out.push_str(&"  ".repeat(depth));
    }
}

fn quote(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if u32::from(control) < 0x20 => {
                out.push_str("\\u00");
                for shift in [4, 0] {
                    let digit = (u32::from(control) >> shift) & 0xf;
                    out.push(char::from_digit(digit, 16).unwrap_or('0'));
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
}
