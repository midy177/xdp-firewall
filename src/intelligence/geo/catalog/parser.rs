use super::super::ipdeny_country_url;
use anyhow::{Result, bail};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::intelligence::geo) struct IpdenyIndexEntry {
    pub country: String,
    pub name: String,
    pub url: String,
    pub last_modified: Option<String>,
    pub size_bytes: Option<i64>,
}

pub(in crate::intelligence::geo) fn parse_ipdeny_index(
    body: &str,
) -> Result<Vec<IpdenyIndexEntry>> {
    let mut entries = Vec::new();
    let last_modified = parse_ipdeny_root_last_updated(body);
    for line in body.lines() {
        if let Some(entry) = parse_ipdeny_index_line(line, last_modified.clone())? {
            entries.push(entry);
        }
    }
    if entries.is_empty() {
        bail!("IPdeny country block page did not contain country zone files");
    }
    Ok(entries)
}

fn parse_ipdeny_index_line(
    line: &str,
    last_modified: Option<String>,
) -> Result<Option<IpdenyIndexEntry>> {
    let text = strip_html(line);
    if !text.contains(".zone") {
        return Ok(None);
    }
    let Some((name, country)) = parse_ipdeny_country_heading(&text) else {
        return Ok(None);
    };
    Ok(Some(IpdenyIndexEntry {
        url: ipdeny_country_url(&country)?,
        country,
        name,
        last_modified,
        size_bytes: None,
    }))
}

fn parse_ipdeny_root_last_updated(body: &str) -> Option<String> {
    body.lines().map(strip_html).find_map(|line| {
        line.split_once("Zone files last updated:")
            .map(|(_, value)| value.trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

fn parse_ipdeny_country_heading(text: &str) -> Option<(String, String)> {
    let download_index = text.find("[download").or_else(|| text.find(" download "))?;
    let heading = text[..download_index].trim();
    let code_start = heading.rfind('(')?;
    let code_end = heading[code_start..].find(')')? + code_start;
    let code = heading[code_start + 1..code_end].trim();
    if code.len() != 2 || !code.bytes().all(|byte| byte.is_ascii_alphabetic()) {
        return None;
    }
    let name = heading[..code_start].trim();
    (!name.is_empty()).then(|| (title_case_country_name(name), code.to_ascii_uppercase()))
}

fn title_case_country_name(name: &str) -> String {
    name.split_whitespace()
        .map(title_case_word)
        .collect::<Vec<_>>()
        .join(" ")
}

fn title_case_word(word: &str) -> String {
    let mut chars = word.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut output = String::new();
    output.extend(first.to_uppercase());
    output.push_str(&chars.as_str().to_ascii_lowercase());
    output
}

fn strip_html(value: &str) -> String {
    let mut output = String::with_capacity(value.len());
    let mut in_tag = false;
    for ch in value.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                output.push(' ');
            }
            _ if !in_tag => output.push(ch),
            _ => {}
        }
    }
    output
}
