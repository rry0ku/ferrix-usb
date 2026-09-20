pub fn sanitize_terminal_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;

    while i < chars.len() {
        let c = chars[i];

        if c == '\x1b' {
            i += 1;
            if i < chars.len() {
                let next = chars[i];
                if next == '[' {
                    i += 1;
                    while i < chars.len() {
                        let ch = chars[i];
                        i += 1;
                        if ('@'..='~').contains(&ch) {
                            break;
                        }
                    }
                } else if next == ']' || next == 'P' || next == '_' || next == '^' {
                    i += 1;
                    while i < chars.len() {
                        let ch = chars[i];
                        i += 1;
                        if ch == '\x07' || (ch == '\\' && i >= 2 && chars[i - 2] == '\x1b') {
                            break;
                        }
                    }
                } else {
                    i += 1;
                }
            }
            continue;
        }

        match c {
            '\u{202A}' => out.push_str("[LRE]"),
            '\u{202B}' => out.push_str("[RLE]"),
            '\u{202C}' => out.push_str("[PDF]"),
            '\u{202D}' => out.push_str("[LRO]"),
            '\u{202E}' => out.push_str("[RLO]"),
            '\u{2066}' => out.push_str("[LRI]"),
            '\u{2067}' => out.push_str("[RLI]"),
            '\u{2068}' => out.push_str("[FSI]"),
            '\u{2069}' => out.push_str("[PDI]"),
            '\u{200E}' => out.push_str("[LRM]"),
            '\u{200F}' => out.push_str("[RLM]"),
            '\u{061C}' => out.push_str("[ALM]"),
            '\n' => out.push('\n'),
            '\t' => out.push_str("    "),
            c if (c as u32) < 0x20 || (c as u32) == 0x7F => {
                out.push_str(&format!("\\x{:02x}", c as u32));
            }
            c => out.push(c),
        }

        i += 1;
    }

    out
}

pub fn sanitize_single_line(s: &str) -> String {
    sanitize_terminal_string(s).replace('\n', " ")
}
