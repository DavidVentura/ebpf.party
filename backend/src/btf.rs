use object::{Object, ObjectSection};
use std::collections::HashMap;

/// One `.BTF.ext` line-info record: instruction byte offset within its
/// program section, and the source line/column it maps to.
#[derive(Debug, Clone, Copy)]
struct LineRec {
    insn_off: u32,
    line: u32,
    col: u32,
}

/// Per-program-section line info parsed from `.BTF.ext`. Unlike `.debug_line`,
/// this is explicitly keyed by section, so it resolves correctly in
/// multi-program objects (each `SEC()` is its own program with its own
/// instruction offsets starting at 0).
pub struct BtfLines {
    sections: HashMap<String, Vec<LineRec>>,
}

fn u16le(b: &[u8], o: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(o..o + 2)?.try_into().ok()?))
}
fn u32le(b: &[u8], o: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(o..o + 4)?.try_into().ok()?))
}

fn btf_string(btf: &[u8], str_base: usize, off: u32) -> Option<String> {
    let start = str_base + off as usize;
    let end = btf[start..].iter().position(|&c| c == 0)? + start;
    Some(String::from_utf8_lossy(&btf[start..end]).into_owned())
}

impl BtfLines {
    pub fn parse(elf_data: &[u8]) -> Option<BtfLines> {
        let file = object::File::parse(elf_data).ok()?;
        let btf = file.section_by_name(".BTF")?.uncompressed_data().ok()?;
        let ext = file.section_by_name(".BTF.ext")?.uncompressed_data().ok()?;

        if u16le(&btf, 0)? != 0xeB9F {
            return None;
        }
        let btf_hdr_len = u32le(&btf, 4)? as usize;
        let str_off = u32le(&btf, 16)? as usize;
        let str_base = btf_hdr_len + str_off;

        let ext_hdr_len = u32le(&ext, 4)? as usize;
        let line_info_off = u32le(&ext, 16)? as usize;
        let line_info_len = u32le(&ext, 20)? as usize;
        let base = ext_hdr_len + line_info_off;
        let rec_size = u32le(&ext, base)? as usize;
        if rec_size < 16 {
            return None;
        }

        let mut sections: HashMap<String, Vec<LineRec>> = HashMap::new();
        let end = base + line_info_len;
        let mut p = base + 4;
        while p + 8 <= end {
            let sec_name_off = u32le(&ext, p)?;
            let num = u32le(&ext, p + 4)? as usize;
            p += 8;
            let name = btf_string(&btf, str_base, sec_name_off)?;
            let mut recs = Vec::with_capacity(num);
            for _ in 0..num {
                let insn_off = u32le(&ext, p)?;
                let line_col = u32le(&ext, p + 12)?;
                recs.push(LineRec {
                    insn_off,
                    line: line_col >> 10,
                    col: line_col & 0x3ff,
                });
                p += rec_size;
            }
            recs.sort_by_key(|r| r.insn_off);
            sections.insert(name, recs);
        }
        Some(BtfLines { sections })
    }

    /// Source line/col of instruction `insn_idx` within `section`.
    pub fn resolve(&self, section: &str, insn_idx: u32) -> Option<(u32, u32)> {
        let recs = self.sections.get(section)?;
        let target = insn_idx * 8;
        let mut best: Option<&LineRec> = None;
        for r in recs {
            if r.insn_off > target {
                break;
            }
            best = Some(r);
        }
        let r = best?;
        (r.line != 0).then_some((r.line, r.col))
    }

    pub fn section_names(&self) -> impl Iterator<Item = &String> {
        self.sections.keys()
    }
}

/// Identify which program section a verifier log belongs to by matching the
/// opcode bytes it disassembles (`N: (bf) ...`) against each section's
/// bytecode. Relocations never touch the opcode byte, so this is stable.
pub fn identify_section(elf_data: &[u8], log: &str, candidates: &[String]) -> Option<String> {
    let file = object::File::parse(elf_data).ok()?;

    let mut want: Vec<(usize, u8)> = Vec::new();
    for line in log.lines() {
        let line = line.trim_start();
        let Some((idx_str, rest)) = line.split_once(": (") else {
            continue;
        };
        let Ok(idx) = idx_str.parse::<usize>() else {
            continue;
        };
        let Some(op_str) = rest.get(0..2) else {
            continue;
        };
        if let Ok(op) = u8::from_str_radix(op_str, 16) {
            want.push((idx, op));
        }
        if want.len() >= 8 {
            break;
        }
    }
    if want.is_empty() {
        return None;
    }

    for name in candidates {
        let Some(sec) = file.section_by_name(name) else {
            continue;
        };
        let Ok(code) = sec.uncompressed_data() else {
            continue;
        };
        let matches = want.iter().all(|&(idx, op)| {
            code.get(idx * 8).map(|&b| b == op).unwrap_or(false)
        });
        if matches {
            return Some(name.clone());
        }
    }
    None
}
