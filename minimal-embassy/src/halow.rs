//! Wi‑Fi HaLow (TX‑AH) control over UART — mirrors `halow_mesh` Arduino demo.
//!
//! Pins: MCU RX = GPIO4, MCU TX = GPIO5 (HaLow TX/RX crossed). UART 115200 8N1.

use core::fmt::Write as _;

use embedded_hal::delay::DelayNs;
use embassy_time::{Duration, Timer};
use esp_hal::delay::Delay;
use esp_hal::uart::{Error, Uart};
use esp_hal::{Async, Blocking};
use heapless::Vec;

/// Max application payload per `AT+TXDATA` (from C++ `MAX_PAYLOAD`).
pub const MAX_PAYLOAD: usize = 1486;
pub const ETH_HEADER_LEN: usize = 14;
const RXDATA_PREFIX: &[u8] = b"+RXDATA:";

/// Ethernet header template: broadcast dest, zero src until [`HalowDriver::fetch_mac`].
pub fn default_eth_header() -> [u8; ETH_HEADER_LEN] {
    [
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ]
}

fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Drain RX FIFO (non-blocking).
pub fn drain_rx(uart: &mut Uart<'_, Blocking>) {
    let mut tmp = [0u8; 64];
    while uart.read_buffered_bytes(&mut tmp).unwrap_or(0) > 0 {}
}

/// Send `cmd` with CRLF, then read until `OK` / `ERROR` or ~1.5s (like `sendCmdSafe`).
pub fn send_cmd_safe(uart: &mut Uart<'_, Blocking>, cmd: &str) {
    drain_rx(uart);
    let mut line: heapless::String<160> = heapless::String::new();
    let _ = line.push_str(cmd);
    let _ = line.push_str("\r\n");
    let _ = uart.write_bytes(line.as_bytes());
    let mut buf = Vec::<u8, 512>::new();
    let mut delay = Delay::new();
    for _ in 0..1500 {
        delay.delay_ms(1u32);
        let mut tmp = [0u8; 64];
        let n = uart.read_buffered_bytes(&mut tmp).unwrap_or(0);
        for b in tmp.iter().take(n) {
            let _ = buf.push(*b);
        }
        if response_done(&buf) {
            break;
        }
    }
}

fn response_done(buf: &[u8]) -> bool {
    let s = buf.len();
    if s >= 2 && &buf[s - 2..] == b"OK" {
        return true;
    }
    if s >= 5 && &buf[s - 5..] == b"ERROR" {
        return true;
    }
    if contains_subslice(buf, b"stop") || contains_subslice(buf, b"pri_chan") {
        return true;
    }
    if contains_subslice(buf, b"ret =") {
        return true;
    }
    false
}

fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle)
}

/// Run AT setup sequence (EU mesh / fixed channel) from your `setup()`.
pub fn configure_radio(uart: &mut Uart<'_, Blocking>) {
    send_cmd_safe(uart, "AT+RADIO_ONOFF=0");
    Delay::new().delay_ms(200u32);
    send_cmd_safe(uart, "AT+SYSDBG=LMAC,0");
    send_cmd_safe(uart, "AT+PRINT_PERIOD=0");
    send_cmd_safe(uart, "AT+MODE=GROUP");
    send_cmd_safe(uart, "AT+SSID=Mesh1");
    send_cmd_safe(uart, "AT+KEYMGMT=NONE");
    send_cmd_safe(uart, "AT+BSS_BW=1");
    send_cmd_safe(uart, "AT+COUNTRY_REGION=EU");
    send_cmd_safe(uart, "AT+FREQ_RANGE=8630,8640");
    send_cmd_safe(uart, "AT+ACS_START=0");
    send_cmd_safe(uart, "AT+PRI_CHAN=1");
    send_cmd_safe(uart, "AT+RADIO_ONOFF=1");
    Delay::new().delay_ms(1000u32);
    send_cmd_safe(uart, "AT+ACS_START=0");
    send_cmd_safe(uart, "AT+PRI_CHAN=1");
}

/// Query module MAC and write source bytes into `eth_header[6..12]`.
pub fn fetch_mac_into_header(uart: &mut Uart<'_, Blocking>, eth_header: &mut [u8; ETH_HEADER_LEN]) {
    drain_rx(uart);
    Delay::new().delay_ms(100u32);
    let _ = uart.write_bytes(b"AT+MAC_ADDR=?\r\n");
    let mut buf = Vec::<u8, 512>::new();
    let mut delay = Delay::new();
    for _ in 0..1500 {
        delay.delay_ms(1u32);
        let mut tmp = [0u8; 64];
        let n = uart.read_buffered_bytes(&mut tmp).unwrap_or(0);
        for b in tmp.iter().take(n) {
            let _ = buf.push(*b);
        }
        if buf.len() > 10 && buf.iter().any(|c| *c == b':' || *c == b'-') {
            break;
        }
    }
    let buf_slice = buf.as_slice();
    let buf_len = buf_slice.len();
    for p in 0..buf_len.saturating_sub(16) {
        let a = match hex_nibble(buf_slice[p]) {
            Some(x) => x,
            None => continue,
        };
        let b = match hex_nibble(buf_slice[p + 1]) {
            Some(x) => x,
            None => continue,
        };
        let sep = buf_slice[p + 2];
        if a <= 0x0f && b <= 0x0f && (sep == b':' || sep == b'-') {
            for i in 0..6 {
                let off = p + i * 3;
                if off + 1 < buf_len {
                    let h = match hex_nibble(buf_slice[off]) {
                        Some(x) => x,
                        None => break,
                    };
                    let l = match hex_nibble(buf_slice[off + 1]) {
                        Some(x) => x,
                        None => break,
                    };
                    eth_header[6 + i] = (h << 4) | l;
                }
            }
            break;
        }
    }
}

/// Wait for a line ending in `OK` after announcing TX length (like `waitOk`).
#[allow(dead_code)]
pub fn wait_ok(uart: &mut Uart<'_, Blocking>, timeout_ms: u32) -> bool {
    let mut buf = Vec::<u8, 128>::new();
    let mut delay = Delay::new();
    for _ in 0..timeout_ms {
        delay.delay_ms(1u32);
        let mut tmp = [0u8; 32];
        let n = uart.read_buffered_bytes(&mut tmp).unwrap_or(0);
        for b in tmp.iter().take(n) {
            let _ = buf.push(*b);
        }
        if buf.len() >= 2 && buf.as_slice().windows(2).any(|w| w == b"OK") {
            return true;
        }
        if buf.as_slice().windows(5).any(|w| w == b"ERROR") {
            return false;
        }
    }
    false
}

/// Send payload with fake Ethernet header (`AT+TXDATA` + binary burst).
#[allow(dead_code)]
pub fn send_to_halow(
    uart: &mut Uart<'_, Blocking>,
    eth_header: &[u8; ETH_HEADER_LEN],
    data: &[u8],
) -> Result<(), Error> {
    if data.is_empty() || data.len() > MAX_PAYLOAD {
        return Ok(());
    }
    let total_len = ETH_HEADER_LEN + data.len();
    drain_rx(uart);
    let mut hdr = heapless::String::<32>::new();
    let _ = write!(&mut hdr, "AT+TXDATA={}\r\n", total_len);
    uart.write_bytes(hdr.as_bytes())?;
    if !wait_ok(uart, 100) {
        return Ok(());
    }
    uart.write_bytes(eth_header)?;
    uart.write_bytes(data)?;
    Ok(())
}

/// How far we search for a `+RXDATA:` occurrence (UART may have `OK\r\n` etc. in front).
const RXDATA_PREFIX_SEARCH_MAX: usize = 512;
/// Only this many bytes after `+RXDATA:` are treated as the ASCII line — never scan into binary,
/// or a `\n` / `\r` inside the Ethernet header / payload can be mistaken for end-of-line.
const RXDATA_ASCII_LINE_MAX: usize = 64;

/// Prefer the **rightmost** `+RXDATA:` that starts a line (or buffer start). If the last match in
/// the window is a false positive (e.g. bytes before `+` are not a line break), scan backward for
/// an earlier valid marker — otherwise [`rxdata_header`] returns `None` and we discard hundreds of
/// bytes as "assemble failed".
fn find_rxdata_prefix(buf: &[u8]) -> Option<usize> {
    let search = buf.len().min(RXDATA_PREFIX_SEARCH_MAX);
    let mut end = search;
    let mut fallback_any = None;
    while end >= RXDATA_PREFIX.len() {
        let slice = &buf[..end];
        let rel = slice
            .windows(RXDATA_PREFIX.len())
            .rposition(|w| w == RXDATA_PREFIX)?;
        if fallback_any.is_none() {
            fallback_any = Some(rel);
        }
        if rel == 0 || matches!(buf[rel - 1], b'\r' | b'\n') {
            return Some(rel);
        }
        end = rel;
    }
    // If we did not find a line-boundary marker, fall back to the rightmost plain match.
    // This is less strict but prevents frequent desync drops in noisy mixed UART streams.
    fallback_any
}

/// Parse `+RXDATA:<len>` line and return `(data_start, declared_len)`.
fn rxdata_header(buf: &[u8]) -> Option<(usize, usize)> {
    let pos = find_rxdata_prefix(buf)?;
    let after_prefix = pos + RXDATA_PREFIX.len();
    let ascii_end = (after_prefix + RXDATA_ASCII_LINE_MAX).min(buf.len());

    let mut declared_len: usize = 0;
    let mut saw_digit = false;
    let mut line_end: Option<usize> = None;

    for i in after_prefix..ascii_end {
        let c = buf[i];
        if c.is_ascii_digit() {
            saw_digit = true;
            declared_len = declared_len
                .saturating_mul(10)
                .saturating_add((c - b'0') as usize);
            continue;
        }
        if buf[i] == b'\r' && i + 1 < buf.len() && buf[i + 1] == b'\n' {
            line_end = Some(i + 2);
            break;
        }
        if buf[i] == b'\n' {
            line_end = Some(i + 1);
            break;
        }
        if buf[i] == b'\r' {
            line_end = Some(i + 1);
            break;
        }
    }

    let start = line_end?;
    if !saw_digit {
        return None;
    }
    Some((start, declared_len))
}

/// If `buf` contains a full beacon echo, returns the full post-line frame bytes
/// (`ETH_HEADER_LEN + BEACON_LEN`) and how many bytes to remove from the front of
/// the RX buffer (one UART frame; trailing AT noise stays for the next read).
pub fn try_take_beacon_frame(buf: &[u8]) -> Option<(&[u8], usize)> {
    let (ds, declared_len) = rxdata_header(buf)?;
    // Accept any declared RX frame that has at least an Ethernet header.
    // Some firmware variants prepend/append metadata around app payload.
    if declared_len < ETH_HEADER_LEN {
        return None;
    }
    if declared_len > 1900 {
        return None;
    }
    let end = ds.checked_add(declared_len)?;
    if buf.len() < end {
        return None;
    }
    Some((&buf[ds..end], end))
}

/// `true` while we still need more bytes for a full beacon after the header line.
pub fn reticulum_beacon_incomplete(buf: &[u8]) -> bool {
    let Some((ds, declared_len)) = rxdata_header(buf) else {
        // No RXDATA marker found yet: treat as not-a-frame so caller can discard noise quickly.
        return false;
    };
    if declared_len < ETH_HEADER_LEN || declared_len > 1900 {
        return false;
    }
    buf.len() < ds + declared_len
}

/// Wait for `OK` / `ERROR` after an AT line (async).
pub async fn wait_ok_async(uart: &mut Uart<'_, Async>, timeout_ms: u32) -> bool {
    let mut buf = Vec::<u8, 128>::new();
    for _ in 0..timeout_ms {
        Timer::after(Duration::from_millis(1)).await;
        let mut tmp = [0u8; 64];
        let n = uart.read_buffered_bytes(&mut tmp).unwrap_or(0);
        for b in tmp.iter().take(n) {
            let _ = buf.push(*b);
        }
        if buf.windows(2).any(|w| w == b"OK") {
            return true;
        }
        if buf.windows(5).any(|w| w == b"ERROR") {
            return false;
        }
    }
    false
}

/// `AT+TXDATA` + Ethernet header + payload (async).
///
/// Does **not** drain RX first — draining would drop peer traffic (Arduino `sendToHaLow` does not
/// clear the RX buffer before `AT+TXDATA`).
pub async fn send_to_halow_async(
    uart: &mut Uart<'_, Async>,
    eth_header: &[u8; ETH_HEADER_LEN],
    data: &[u8],
) -> Result<(), Error> {
    if data.is_empty() || data.len() > MAX_PAYLOAD {
        return Ok(());
    }
    let mut hdr = heapless::String::<40>::new();
    let _ = write!(&mut hdr, "AT+TXDATA={}\r\n", ETH_HEADER_LEN + data.len());
    uart.write_async(hdr.as_bytes()).await?;
    if !wait_ok_async(uart, 100).await {
        return Ok(());
    }

    // Some module/firmware combinations appear to corrupt trailing bytes when
    // large payloads are written in one burst. Chunked pacing is slower but
    // more reliable for integrity-sensitive payloads (beacon signatures).
    const CHUNK: usize = 32;
    for chunk in eth_header.chunks(CHUNK) {
        uart.write_async(chunk).await?;
        Timer::after(Duration::from_millis(1)).await;
    }
    for chunk in data.chunks(CHUNK) {
        uart.write_async(chunk).await?;
        Timer::after(Duration::from_millis(1)).await;
    }
    Ok(())
}
