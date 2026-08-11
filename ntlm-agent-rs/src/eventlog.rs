// NTLM-Analyzer - find out who still uses NTLM in your Active Directory.
// Copyright (C) 2026  Nobrac / Carbon / NoPCAP
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Liest Windows-Event-Logs ueber `wevtutil qe ... /f:xml /e:Events` und parst
//! das Ergebnis mit roxmltree. Gleiche XPath-Logik wie das PowerShell-Skript:
//! inkrementell per EventRecordID-Wasserzeichen, erster Lauf per Zeitfenster.

use std::collections::HashMap;

/// Ein roh geparstes Event: System-Felder + benannte und positionsbasierte Data-Werte.
pub struct RawEvent {
    pub record_id: i64,
    pub event_id: i64,
    pub time: String, // ISO, auf Sekunden gekuerzt (YYYY-MM-DDTHH:MM:SS)
    pub named: HashMap<String, String>,
    pub positional: Vec<String>,
    /// Gerenderter Meldungstext (nur bei /f:RenderedXml gefuellt). Wird fuer die
    /// erweiterten 40xx-Events genutzt, deren XML-Feldnamen nicht dokumentiert
    /// sind - dort sind die Beschriftungen im Text die zuverlaessigere Quelle.
    pub message: Option<String>,
}

/// Sammelt alle neuen Events eines Logs (mit interner "Drain"-Schleife, damit
/// auch grosse Rueckstaende in einem Zyklus aufgeholt werden).
/// Rueckgabe: (Events, hoechste tatsaechlich gelesene RecordID).
pub fn collect(
    log: &str,
    id_clause: &str,
    data_clause: &str,
    first_window_ms: i64,
    last: Option<i64>,
    rendered: bool,
) -> Result<(Vec<RawEvent>, i64), String> {
    const CAP: u32 = 500;
    let mut all: Vec<RawEvent> = Vec::new();
    let mut max_seen = last.unwrap_or(0);
    let mut cursor = last;

    loop {
        let xpath = build_xpath(id_clause, data_clause, first_window_ms, cursor);
        let raw = run_wevtutil(log, &xpath, CAP, rendered)?;
        let batch = parse_events(&raw)?;
        if batch.is_empty() {
            break;
        }
        let bmax = batch.iter().map(|e| e.record_id).max().unwrap_or(0);
        if bmax > max_seen {
            max_seen = bmax;
        }
        let got = batch.len();
        all.extend(batch);

        // Schutz gegen Endlosschleife: wenn die RecordID nicht steigt, abbrechen.
        if cursor.is_some_and(|c| bmax <= c) {
            break;
        }
        cursor = Some(bmax);
        if (got as u32) < CAP {
            break;
        }
    }
    Ok((all, max_seen))
}

fn build_xpath(
    id_clause: &str,
    data_clause: &str,
    first_window_ms: i64,
    last: Option<i64>,
) -> String {
    let time_or_rec = match last {
        Some(l) => format!("EventRecordID > {l}"),
        None => format!("TimeCreated[timediff(@SystemTime) <= {first_window_ms}]"),
    };
    let mut xp = format!("*[System[({id_clause}) and {time_or_rec}]]");
    if !data_clause.is_empty() {
        xp.push_str(" and ");
        xp.push_str(data_clause);
    }
    xp
}

fn run_wevtutil(log: &str, xpath: &str, count: u32, rendered: bool) -> Result<String, String> {
    let output = std::process::Command::new(crate::config::system32("wevtutil.exe"))
        .arg("qe")
        .arg(log)
        .arg(format!("/q:{xpath}"))
        .arg(if rendered { "/f:RenderedXml" } else { "/f:xml" })
        .arg(format!("/c:{count}"))
        .arg("/rd:false")
        .arg("/e:Events")
        .output()
        .map_err(|e| format!("wevtutil-Start: {e}"))?;

    if !output.status.success() {
        let err = String::from_utf8_lossy(&output.stderr);
        let msg = err.trim();
        if msg.is_empty() {
            return Ok(String::new()); // kein Treffer ist kein Fehler
        }
        return Err(msg.to_string());
    }
    Ok(decode_output(&output.stdout))
}

/// wevtutil liefert in der Regel UTF-8; je nach System/Locale aber auch UTF-16.
/// Anhand des Byte-Order-Marks bzw. des ersten Zeichens '<' robust dekodieren,
/// damit das Parsen nicht an der Kodierung scheitert.
fn decode_output(bytes: &[u8]) -> String {
    if bytes.starts_with(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(&bytes[3..]).into_owned(); // UTF-8 mit BOM
    }
    if bytes.starts_with(&[0xFF, 0xFE]) {
        return decode_utf16(&bytes[2..], true); // UTF-16LE mit BOM
    }
    if bytes.starts_with(&[0xFE, 0xFF]) {
        return decode_utf16(&bytes[2..], false); // UTF-16BE mit BOM
    }
    if bytes.len() >= 2 && bytes[0] == 0x3C && bytes[1] == 0x00 {
        return decode_utf16(bytes, true); // "<\0..." = UTF-16LE ohne BOM
    }
    if bytes.len() >= 2 && bytes[0] == 0x00 && bytes[1] == 0x3C {
        return decode_utf16(bytes, false); // "\0<..." = UTF-16BE ohne BOM
    }
    String::from_utf8_lossy(bytes).into_owned() // Standardfall: UTF-8
}

fn decode_utf16(bytes: &[u8], little_endian: bool) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| {
            if little_endian {
                u16::from_le_bytes([c[0], c[1]])
            } else {
                u16::from_be_bytes([c[0], c[1]])
            }
        })
        .collect();
    String::from_utf16_lossy(&units)
}

pub fn parse_events(xml: &str) -> Result<Vec<RawEvent>, String> {
    let cleaned = xml.trim_start_matches('\u{feff}').trim();
    if cleaned.is_empty() {
        return Ok(Vec::new());
    }
    let doc = roxmltree::Document::parse(cleaned).map_err(|e| format!("XML: {e}"))?;
    let mut out = Vec::new();

    for ev in doc
        .root_element()
        .children()
        .filter(|n| n.is_element() && n.tag_name().name() == "Event")
    {
        let system = child_node(&ev, "System");
        let (record_id, event_id, time) = match system {
            Some(s) => (
                child_text(&s, "EventRecordID")
                    .and_then(|v| v.trim().parse::<i64>().ok())
                    .unwrap_or(0),
                child_text(&s, "EventID")
                    .and_then(|v| v.trim().parse::<i64>().ok())
                    .unwrap_or(0),
                child_node(&s, "TimeCreated")
                    .and_then(|n| n.attribute("SystemTime"))
                    .map(iso_seconds)
                    .unwrap_or_default(),
            ),
            None => (0, 0, String::new()),
        };

        let mut named: HashMap<String, String> = HashMap::new();
        let mut positional: Vec<String> = Vec::new();

        if let Some(ed) = child_node(&ev, "EventData") {
            for d in ed
                .children()
                .filter(|n| n.is_element() && n.tag_name().name() == "Data")
            {
                let val = d.text().unwrap_or("").to_string();
                positional.push(val.clone());
                if let Some(name) = d.attribute("Name") {
                    named.insert(name.to_string(), val);
                }
            }
        } else if let Some(ud) = child_node(&ev, "UserData") {
            if let Some(inner) = ud.children().find(|n| n.is_element()) {
                for d in inner.children().filter(|n| n.is_element()) {
                    let val = d.text().unwrap_or("").to_string();
                    positional.push(val.clone());
                    named.insert(d.tag_name().name().to_string(), val);
                }
            }
        }

        // Bei /f:RenderedXml haengt der gerenderte Text unter RenderingInfo/Message.
        let message = child_node(&ev, "RenderingInfo")
            .and_then(|ri| child_text(&ri, "Message"))
            .map(|m| m.trim().to_string())
            .filter(|m| !m.is_empty());

        out.push(RawEvent {
            record_id,
            event_id,
            time,
            named,
            positional,
            message,
        });
    }
    Ok(out)
}

fn child_node<'a, 'i>(
    parent: &roxmltree::Node<'a, 'i>,
    name: &str,
) -> Option<roxmltree::Node<'a, 'i>> {
    parent
        .children()
        .find(|n| n.is_element() && n.tag_name().name() == name)
}

fn child_text(parent: &roxmltree::Node, name: &str) -> Option<String> {
    child_node(parent, name).and_then(|n| n.text().map(|t| t.to_string()))
}

fn iso_seconds(s: &str) -> String {
    s.chars().take(19).collect()
}
