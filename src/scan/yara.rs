use crate::core::{Confidence, Finding, Location, MediaPath, Severity, StageError};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YaraStringPattern {
    Ascii(Vec<u8>, bool),
    Wide(Vec<u8>, bool),
    Hex(Vec<Option<u8>>),
}

impl YaraStringPattern {
    pub fn matches_at(&self, data: &[u8], offset: usize) -> bool {
        match self {
            YaraStringPattern::Ascii(pattern, nocase) => {
                if offset + pattern.len() > data.len() {
                    return false;
                }
                let slice = &data[offset..offset + pattern.len()];
                if *nocase {
                    slice.iter().zip(pattern.iter()).all(|(a, b)| {
                        a.to_ascii_lowercase() == b.to_ascii_lowercase()
                    })
                } else {
                    slice == pattern.as_slice()
                }
            }
            YaraStringPattern::Wide(pattern, nocase) => {
                let wide_len = pattern.len().saturating_mul(2);
                if offset + wide_len > data.len() {
                    return false;
                }
                for (i, &b) in pattern.iter().enumerate() {
                    let byte_offset = offset + (i * 2);
                    let low = data[byte_offset];
                    let high = data[byte_offset + 1];
                    if high != 0 {
                        return false;
                    }
                    if *nocase {
                        if low.to_ascii_lowercase() != b.to_ascii_lowercase() {
                            return false;
                        }
                    } else if low != b {
                        return false;
                    }
                }
                true
            }
            YaraStringPattern::Hex(pattern) => {
                if offset + pattern.len() > data.len() {
                    return false;
                }
                for (i, expected) in pattern.iter().enumerate() {
                    if let Some(byte) = expected {
                        if data[offset + i] != *byte {
                            return false;
                        }
                    }
                }
                true
            }
        }
    }

    pub fn find_matches(&self, data: &[u8]) -> Vec<usize> {
        let mut matches = Vec::new();
        if data.is_empty() {
            return matches;
        }
        for i in 0..data.len() {
            if self.matches_at(data, i) {
                matches.push(i);
            }
        }
        matches
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConditionExpr {
    StringRef(String),
    AnyOfThem,
    AllOfThem,
    Not(Box<ConditionExpr>),
    And(Box<ConditionExpr>, Box<ConditionExpr>),
    Or(Box<ConditionExpr>, Box<ConditionExpr>),
    Boolean(bool),
}

impl ConditionExpr {
    pub fn evaluate(&self, string_matches: &HashMap<String, Vec<usize>>) -> bool {
        match self {
            ConditionExpr::StringRef(name) => {
                string_matches.get(name).map(|v| !v.is_empty()).unwrap_or(false)
            }
            ConditionExpr::AnyOfThem => {
                string_matches.values().any(|v| !v.is_empty())
            }
            ConditionExpr::AllOfThem => {
                !string_matches.is_empty() && string_matches.values().all(|v| !v.is_empty())
            }
            ConditionExpr::Not(inner) => !inner.evaluate(string_matches),
            ConditionExpr::And(left, right) => {
                left.evaluate(string_matches) && right.evaluate(string_matches)
            }
            ConditionExpr::Or(left, right) => {
                left.evaluate(string_matches) || right.evaluate(string_matches)
            }
            ConditionExpr::Boolean(b) => *b,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct YaraRule {
    pub name: String,
    pub meta: HashMap<String, String>,
    pub strings: HashMap<String, YaraStringPattern>,
    pub condition: ConditionExpr,
}

impl YaraRule {
    pub fn scan(&self, data: &[u8]) -> Option<Vec<(String, usize)>> {
        let mut string_matches = HashMap::new();
        for (id, pattern) in &self.strings {
            let matches = pattern.find_matches(data);
            string_matches.insert(id.clone(), matches);
        }

        if self.condition.evaluate(&string_matches) {
            let mut matched_details = Vec::new();
            for (id, offsets) in string_matches {
                for off in offsets {
                    matched_details.push((id.clone(), off));
                }
            }
            Some(matched_details)
        } else {
            None
        }
    }
}

pub fn parse_yara_rules(source: &str) -> Result<Vec<YaraRule>, StageError> {
    let mut rules = Vec::new();
    let lines: Vec<&str> = source.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let raw = lines[i].trim();
        if raw.is_empty() || raw.starts_with("//") || raw.starts_with('#') {
            i += 1;
            continue;
        }

        if let Some(rule_header) = raw.strip_prefix("rule ") {
            let rule_name = rule_header.trim_end_matches('{').trim().to_string();
            if rule_name.is_empty() {
                return Err(StageError::Parse("YARA rule missing name".to_string()));
            }

            i += 1;
            let mut meta = HashMap::new();
            let mut strings = HashMap::new();
            let mut condition_lines = Vec::new();
            let mut section = "none";

            while i < lines.len() {
                let line = lines[i].trim();
                if line == "}" {
                    i += 1;
                    break;
                }

                if line == "meta:" {
                    section = "meta";
                    i += 1;
                    continue;
                } else if line == "strings:" {
                    section = "strings";
                    i += 1;
                    continue;
                } else if line == "condition:" {
                    section = "condition";
                    i += 1;
                    continue;
                }

                match section {
                    "meta" => {
                        if let Some((k, v)) = parse_meta_line(line) {
                            meta.insert(k, v);
                        }
                    }
                    "strings" => {
                        if let Some((k, v)) = parse_string_line(line)? {
                            strings.insert(k, v);
                        }
                    }
                    "condition" => {
                        if !line.is_empty() {
                            condition_lines.push(line);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }

            let cond_str = condition_lines.join(" ");
            let condition = parse_condition(&cond_str)?;

            rules.push(YaraRule {
                name: rule_name,
                meta,
                strings,
                condition,
            });
        } else {
            i += 1;
        }
    }

    Ok(rules)
}

fn parse_meta_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() == 2 {
        let k = parts[0].trim().to_string();
        let v = parts[1].trim().trim_matches('"').trim_matches('\'').to_string();
        Some((k, v))
    } else {
        None
    }
}

fn parse_string_line(line: &str) -> Result<Option<(String, YaraStringPattern)>, StageError> {
    if !line.starts_with('$') {
        return Ok(None);
    }
    let parts: Vec<&str> = line.splitn(2, '=').collect();
    if parts.len() != 2 {
        return Err(StageError::Parse(format!("invalid string definition: {line}")));
    }
    let var_name = parts[0].trim().to_string();
    let rhs = parts[1].trim();

    if let Some(hex_body) = rhs.strip_prefix('{') {
        let hex_content = hex_body.trim_end_matches('}').trim();
        let mut pattern = Vec::new();
        for token in hex_content.split_whitespace() {
            if token == "??" || token == "?" {
                pattern.push(None);
            } else if let Ok(b) = u8::from_str_radix(token, 16) {
                pattern.push(Some(b));
            } else {
                return Err(StageError::Parse(format!("invalid hex byte in YARA: {token}")));
            }
        }
        Ok(Some((var_name, YaraStringPattern::Hex(pattern))))
    } else if let Some(str_body) = rhs.strip_prefix('"') {
        let end_idx = str_body.rfind('"').ok_or_else(|| {
            StageError::Parse(format!("unterminated string literal: {rhs}"))
        })?;
        let str_val = &str_body[..end_idx];
        let modifiers = str_body[end_idx + 1..].trim();
        let nocase = modifiers.contains("nocase");
        let wide = modifiers.contains("wide");

        if wide {
            Ok(Some((
                var_name,
                YaraStringPattern::Wide(str_val.as_bytes().to_vec(), nocase),
            )))
        } else {
            Ok(Some((
                var_name,
                YaraStringPattern::Ascii(str_val.as_bytes().to_vec(), nocase),
            )))
        }
    } else {
        Err(StageError::Parse(format!("unsupported YARA string format: {rhs}")))
    }
}

fn parse_condition(cond: &str) -> Result<ConditionExpr, StageError> {
    let trimmed = cond.trim();
    if trimmed.is_empty() {
        return Ok(ConditionExpr::Boolean(true));
    }
    if trimmed.eq_ignore_ascii_case("any of them") {
        return Ok(ConditionExpr::AnyOfThem);
    }
    if trimmed.eq_ignore_ascii_case("all of them") {
        return Ok(ConditionExpr::AllOfThem);
    }
    if trimmed.eq_ignore_ascii_case("true") {
        return Ok(ConditionExpr::Boolean(true));
    }
    if trimmed.eq_ignore_ascii_case("false") {
        return Ok(ConditionExpr::Boolean(false));
    }

    if let Some(pos) = find_binary_operator(trimmed, " or ") {
        let left = parse_condition(&trimmed[..pos])?;
        let right = parse_condition(&trimmed[pos + 4..])?;
        return Ok(ConditionExpr::Or(Box::new(left), Box::new(right)));
    }

    if let Some(pos) = find_binary_operator(trimmed, " and ") {
        let left = parse_condition(&trimmed[..pos])?;
        let right = parse_condition(&trimmed[pos + 5..])?;
        return Ok(ConditionExpr::And(Box::new(left), Box::new(right)));
    }

    if let Some(rest) = trimmed.strip_prefix("not ") {
        let inner = parse_condition(rest.trim())?;
        return Ok(ConditionExpr::Not(Box::new(inner)));
    }

    if trimmed.starts_with('(') && trimmed.ends_with(')') {
        let inner = &trimmed[1..trimmed.len() - 1];
        return parse_condition(inner);
    }

    if trimmed.starts_with('$') {
        return Ok(ConditionExpr::StringRef(trimmed.to_string()));
    }

    Ok(ConditionExpr::Boolean(false))
}

fn find_binary_operator(s: &str, op: &str) -> Option<usize> {
    let mut depth = 0;
    let bytes = s.as_bytes();
    let op_bytes = op.as_bytes();

    for i in 0..bytes.len() {
        if bytes[i] == b'(' {
            depth += 1;
        } else if bytes[i] == b')' {
            if depth > 0 {
                depth -= 1;
            }
        } else if depth == 0 && i + op_bytes.len() <= bytes.len() {
            let slice = &s[i..i + op_bytes.len()];
            if slice.eq_ignore_ascii_case(op) {
                return Some(i);
            }
        }
    }
    None
}

pub fn load_yara_rules_from_path(path: &Path) -> Result<Vec<YaraRule>, StageError> {
    if path.is_file() {
        let content = fs::read_to_string(path).map_err(|e| {
            StageError::Io(format!("failed to read YARA rule file {}: {e}", path.display()))
        })?;
        parse_yara_rules(&content)
    } else if path.is_dir() {
        let mut all_rules = Vec::new();
        let entries = fs::read_dir(path).map_err(|e| {
            StageError::Io(format!("failed to read YARA rules directory {}: {e}", path.display()))
        })?;
        for entry in entries.flatten() {
            let p = entry.path();
            if p.is_file() {
                if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                    if ext == "yar" || ext == "yara" {
                        if let Ok(content) = fs::read_to_string(&p) {
                            if let Ok(rules) = parse_yara_rules(&content) {
                                all_rules.extend(rules);
                            }
                        }
                    }
                }
            }
        }
        Ok(all_rules)
    } else {
        Err(StageError::Io(format!("YARA path does not exist: {}", path.display())))
    }
}

pub fn scan_data_with_yara(
    data: &[u8],
    rules: &[YaraRule],
    media_path: &MediaPath,
    findings: &mut Vec<Finding>,
) {
    for rule in rules {
        if let Some(matches) = rule.scan(data) {
            let mut match_desc = Vec::new();
            for (id, offset) in matches.iter().take(10) {
                match_desc.push(format!("{id}@0x{offset:x}"));
            }
            let evidence = format!(
                "rule '{}' matched (matched strings: {})",
                rule.name,
                match_desc.join(", ")
            );
            findings.push(Finding {
                id: "FX-YARA-001".to_string(),
                severity: Severity::High,
                confidence: Confidence::High,
                stage: "yara_scan".to_string(),
                location: Location::Path(media_path.clone()),
                reason: format!("YARA rule '{}' matched content", rule.name),
                evidence,
            });
        }
    }
}
