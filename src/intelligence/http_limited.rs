use anyhow::{Context, Result, bail};

pub(super) async fn read_limited_body(
    mut response: reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<String> {
    reject_oversized_content_length(&response, max_bytes, label)?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if body.len() + chunk.len() > max_bytes {
            bail!("{label} response exceeded {max_bytes} bytes");
        }
        body.extend_from_slice(&chunk);
    }
    String::from_utf8(body).with_context(|| format!("{label} returned non-UTF-8 response"))
}

pub(super) async fn read_limited_lines<T, F>(
    mut response: reqwest::Response,
    max_bytes: usize,
    label: &str,
    mut parse_line: F,
) -> Result<Vec<T>>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    reject_oversized_content_length(&response, max_bytes, label)?;
    let mut total = 0_usize;
    let mut carry = Vec::new();
    let mut parsed = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        total += chunk.len();
        if total > max_bytes {
            bail!("{label} response exceeded {max_bytes} bytes");
        }
        carry.extend_from_slice(&chunk);
        drain_complete_lines(&mut carry, &mut parsed, &mut parse_line, label)?;
    }
    parse_remaining_line(&mut carry, &mut parsed, &mut parse_line, label)?;
    Ok(parsed)
}

fn reject_oversized_content_length(
    response: &reqwest::Response,
    max_bytes: usize,
    label: &str,
) -> Result<()> {
    if response
        .content_length()
        .is_some_and(|length| length > max_bytes as u64)
    {
        bail!("{label} response exceeded {max_bytes} bytes");
    }
    Ok(())
}

fn drain_complete_lines<T, F>(
    carry: &mut Vec<u8>,
    parsed: &mut Vec<T>,
    parse_line: &mut F,
    label: &str,
) -> Result<()>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    while let Some(newline) = carry.iter().position(|byte| *byte == b'\n') {
        let mut line = carry.drain(..=newline).collect::<Vec<_>>();
        trim_line_ending(&mut line);
        parse_utf8_line(&line, parsed, parse_line, label)?;
    }
    Ok(())
}

fn parse_remaining_line<T, F>(
    carry: &mut Vec<u8>,
    parsed: &mut Vec<T>,
    parse_line: &mut F,
    label: &str,
) -> Result<()>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    if carry.is_empty() {
        return Ok(());
    }
    trim_line_ending(carry);
    parse_utf8_line(carry, parsed, parse_line, label)
}

fn trim_line_ending(line: &mut Vec<u8>) {
    if line.last() == Some(&b'\n') {
        line.pop();
    }
    if line.last() == Some(&b'\r') {
        line.pop();
    }
}

fn parse_utf8_line<T, F>(
    line: &[u8],
    parsed: &mut Vec<T>,
    parse_line: &mut F,
    label: &str,
) -> Result<()>
where
    F: FnMut(&str) -> Result<Option<T>>,
{
    let line =
        std::str::from_utf8(line).with_context(|| format!("{label} returned non-UTF-8 line"))?;
    if let Some(value) = parse_line(line)? {
        parsed.push(value);
    }
    Ok(())
}
