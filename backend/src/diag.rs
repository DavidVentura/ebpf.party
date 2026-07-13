use crate::dwarf::{self, DwarfDebugInfo, MemberHit, StackVar};
use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorKind {
    NullDeref,
    Unbounded,
    OutOfRange,
    StackOob,
    NegativeMin,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EventKind {
    OriginLoad,
    OriginCall,
    OriginConst,
    Check,
    NullCheck,
    Narrow,
    WalkEnd,
}

impl EventKind {
    fn from_str(s: &str) -> Option<Self> {
        Some(match s {
            "origin_load" => Self::OriginLoad,
            "origin_call" => Self::OriginCall,
            "origin_const" => Self::OriginConst,
            "check" => Self::Check,
            "null_check" => Self::NullCheck,
            "narrow" => Self::Narrow,
            "walk_end" => Self::WalkEnd,
            _ => return None,
        })
    }

    fn is_bound_check(self) -> bool {
        matches!(self, Self::Check | Self::Narrow)
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub struct Loc {
    pub line: u32,
    pub col: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub kind: EventKind,
    pub insn: u32,
    pub cnt: u32,
    pub reg: Option<u8>,
    pub op: Option<String>,
    pub val: Option<i64>,
    pub val_reg: Option<u8>,
    pub loc: Loc,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum Access {
    MapValue { value_size: u32, off: u32, size: u32 },
    Stack { off: i32, size: u32 },
}

/// The memory argument a rejected helper size argument was paired with.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum MemArg {
    Stack { off: i64 },
    MapValue { size: u32, map: Option<String> },
    Mem { size: u32 },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifierDiagnostic {
    pub error: ErrorKind,
    pub reg: u8,
    pub umin: u64,
    pub umax: u64,
    pub off: i64,
    pub map: Option<String>,
    pub mem_arg: Option<MemArg>,
    pub use_insn: u32,
    pub use_loc: Loc,
    pub access: Option<Access>,
    pub events: Vec<Event>,
}

/// Best-effort DWARF facts about the objects a diagnostic refers to.
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct Enrichment {
    pub member: Option<MemberHit>,
    pub stack_var: Option<StackVar>,
}

fn kv<'a>(token: &'a str, key: &str) -> Option<&'a str> {
    token.strip_prefix(key)?.strip_prefix('=')
}

fn parse_loc(s: &str) -> Option<Loc> {
    let mut it = s.rsplitn(3, ':');
    let col = it.next()?.parse().ok()?;
    let line = it.next()?.parse().ok()?;
    Some(Loc { line, col })
}

fn parse_reg(s: &str) -> Option<u8> {
    s.strip_prefix('r')?.parse().ok()
}

fn classify_error(line: &str) -> Option<ErrorKind> {
    if !line.starts_with('R') && !line.starts_with("invalid variable-offset") {
        return None;
    }
    if line.contains("invalid mem access 'map_value_or_null'") {
        return Some(ErrorKind::NullDeref);
    }
    if line.contains("unbounded memory access") {
        return Some(ErrorKind::Unbounded);
    }
    if line.starts_with("invalid variable-offset") && line.contains("stack") {
        return Some(ErrorKind::StackOob);
    }
    if line.contains("value is outside of the allowed memory range") {
        return Some(ErrorKind::OutOfRange);
    }
    if line.contains("min value is negative") {
        return Some(ErrorKind::NegativeMin);
    }
    None
}

/// Extracts the structured diagnostic from a verifier log carrying a DIAG1
/// trailer. Returns None when the log has no (or a malformed) trailer; the
/// raw log is the only output in that case.
pub fn parse(log: &str) -> Option<VerifierDiagnostic> {
    let mut error = None;
    let mut access = None;
    let mut head: Option<VerifierDiagnostic> = None;
    let mut events = Vec::new();

    for line in log.lines() {
        if let Some(kind) = classify_error(line) {
            error = Some(kind);
        }
        if let Some(rest) = line.strip_prefix("invalid access to map value, ") {
            let mut value_size = None;
            let mut off = None;
            let mut size = None;
            for tok in rest.split_whitespace() {
                if let Some(v) = kv(tok, "value_size") {
                    value_size = v.parse().ok();
                } else if let Some(v) = kv(tok, "off") {
                    off = v.parse().ok();
                } else if let Some(v) = kv(tok, "size") {
                    size = v.parse().ok();
                }
            }
            access = Some(Access::MapValue {
                value_size: value_size?,
                off: off?,
                size: size?,
            });
        }
        if line.starts_with("invalid variable-offset") && line.contains("stack") {
            let mut off = None;
            let mut size = None;
            for tok in line.split_whitespace() {
                if let Some(v) = kv(tok, "off") {
                    off = v.parse().ok();
                } else if let Some(v) = kv(tok, "size") {
                    size = v.parse().ok();
                }
            }
            access = Some(Access::Stack {
                off: off?,
                size: size?,
            });
        }
        if let Some(rest) = line.strip_prefix("DIAG1 ") {
            let mut reg = None;
            let mut umin = None;
            let mut umax = None;
            let mut off = None;
            let mut use_insn = None;
            let mut use_loc = None;
            let mut map = None;
            let mut mem_kind = None;
            let mut mem_off = None;
            let mut mem_size = None;
            let mut mem_map = None;
            for tok in rest.split_whitespace() {
                if let Some(v) = kv(tok, "reg") {
                    reg = v.parse().ok();
                } else if let Some(v) = kv(tok, "umin") {
                    umin = v.parse().ok();
                } else if let Some(v) = kv(tok, "umax") {
                    umax = v.parse().ok();
                } else if let Some(v) = kv(tok, "off") {
                    off = v.parse().ok();
                } else if let Some(v) = kv(tok, "use") {
                    use_insn = v.parse().ok();
                } else if let Some(v) = kv(tok, "use_loc") {
                    use_loc = parse_loc(v);
                } else if let Some(v) = kv(tok, "map") {
                    map = Some(v.to_string());
                } else if let Some(v) = kv(tok, "mem_off") {
                    mem_off = v.parse().ok();
                } else if let Some(v) = kv(tok, "mem_size") {
                    mem_size = v.parse().ok();
                } else if let Some(v) = kv(tok, "mem_map") {
                    mem_map = Some(v.to_string());
                } else if let Some(v) = kv(tok, "mem") {
                    mem_kind = Some(v.to_string());
                }
            }
            let mem_arg = match mem_kind.as_deref() {
                Some("fp") => Some(MemArg::Stack { off: mem_off? }),
                Some("map_value") => Some(MemArg::MapValue {
                    size: mem_size?,
                    map: mem_map,
                }),
                Some("mem") => Some(MemArg::Mem { size: mem_size? }),
                _ => None,
            };
            head = Some(VerifierDiagnostic {
                error: error?,
                reg: reg?,
                umin: umin?,
                umax: umax?,
                off: off?,
                map,
                mem_arg,
                use_insn: use_insn?,
                use_loc: use_loc?,
                access,
                events: Vec::new(),
            });
        }
        if let Some(rest) = line.strip_prefix("DIAG1E ") {
            let mut kind = None;
            let mut insn = None;
            let mut cnt = None;
            let mut reg = None;
            let mut op = None;
            let mut val = None;
            let mut val_reg = None;
            let mut loc = None;
            for tok in rest.split_whitespace() {
                if let Some(v) = kv(tok, "kind") {
                    kind = EventKind::from_str(v);
                } else if let Some(v) = kv(tok, "insn") {
                    insn = v.parse().ok();
                } else if let Some(v) = kv(tok, "cnt") {
                    cnt = v.parse().ok();
                } else if let Some(v) = kv(tok, "reg") {
                    reg = parse_reg(v);
                } else if let Some(v) = kv(tok, "op") {
                    op = Some(v.to_string());
                } else if let Some(v) = kv(tok, "val") {
                    val = v.parse().ok();
                } else if let Some(v) = kv(tok, "valreg") {
                    val_reg = parse_reg(v);
                } else if let Some(v) = kv(tok, "loc") {
                    loc = parse_loc(v);
                }
            }
            events.push(Event {
                kind: kind?,
                insn: insn?,
                cnt: cnt?,
                reg,
                op,
                val,
                val_reg,
                loc: loc?,
            });
        }
    }

    let mut diag = head?;
    diag.events = events;
    Some(diag)
}

/// Resolves the diagnostic's frame offsets and map-value offsets against the
/// program's DWARF. Everything here is best-effort: a miss leaves the
/// corresponding field None and the renderer falls back to verifier-level
/// wording.
pub fn enrich(d: &VerifierDiagnostic, elf: &[u8], info: Option<&DwarfDebugInfo>) -> Enrichment {
    let mut e = Enrichment::default();

    if let (Some(map), Some(Access::MapValue { value_size, off, .. })) =
        (&d.map, d.access.as_ref())
    {
        let resolve_off = (*off).min(value_size.saturating_sub(1)) as u64;
        e.member = dwarf::resolve_map_value_member(elf, map, resolve_off)
            .ok()
            .flatten();
    }

    let stack_off = match (&d.mem_arg, d.access.as_ref()) {
        (Some(MemArg::Stack { off }), _) => Some(*off),
        (_, Some(Access::Stack { off, .. })) => Some(*off as i64),
        _ => None,
    };
    if let (Some(off), Some(info)) = (stack_off, info) {
        e.stack_var = match_stack_var(info, off);
    }
    e
}

/// DWARF stack offsets count from the frame's low end; the verifier's are
/// fp-relative. Reconcile via the frame size and require a unique match.
fn match_stack_var(info: &DwarfDebugInfo, fp_off: i64) -> Option<StackVar> {
    let mut hit = None;
    for f in &info.functions {
        let Some(frame) = f
            .stack_vars
            .iter()
            .filter_map(|v| v.size.map(|s| (v.offset + s) as i64))
            .max()
        else {
            continue;
        };
        for v in &f.stack_vars {
            if v.offset as i64 - frame == fp_off {
                if hit.is_some() {
                    return None;
                }
                hit = Some(v.clone());
            }
        }
    }
    hit
}

/// Byte range of the C identifier (or single char) starting at loc.
fn span_at(source: &str, loc: Loc) -> Option<std::ops::Range<usize>> {
    if loc.line == 0 {
        return None;
    }
    let mut offset = 0;
    for (i, line) in source.split_inclusive('\n').enumerate() {
        if i + 1 == loc.line as usize {
            let col = (loc.col.max(1) as usize - 1).min(line.trim_end().len().saturating_sub(1));
            let start = offset + col;
            let ident_len = line[col..]
                .bytes()
                .take_while(|b| b.is_ascii_alphanumeric() || *b == b'_')
                .count()
                .max(1);
            return Some(start..start + ident_len);
        }
        offset += line.len();
    }
    None
}

/// The comparison as the user wrote it, when it is safe to quote: relational
/// ops against a constant. Equality exits of strength-reduced loops would
/// mislead (`jne 800` for `i < 200` over a u32[170]).
fn quoted_cmp(ev: &Event) -> Option<String> {
    let sym = match ev.op.as_deref()? {
        "jgt" | "jsgt" => ">",
        "jge" | "jsge" => ">=",
        "jlt" | "jslt" => "<",
        "jle" | "jsle" => "<=",
        _ => return None,
    };
    Some(format!("`{} {}`", sym, ev.val?))
}

struct Msg {
    title: String,
    primary: (Loc, String),
    context: Vec<(Loc, String)>,
    /// (line, name-to-underline, label) — declaration site of the violated object.
    decl: Option<(u32, String, String)>,
    help: Option<String>,
}

fn decl_note(hit: &MemberHit) -> Option<(u32, String, String)> {
    let line = hit.decl_line? as u32;
    Some((line, hit.name.clone(), "declared here".to_string()))
}

fn var_decl_note(v: &StackVar) -> Option<(u32, String, String)> {
    let line = v.decl_line? as u32;
    Some((line, v.name.clone(), "declared here".to_string()))
}

fn build_msg(d: &VerifierDiagnostic, enrich: &Enrichment) -> Msg {
    let checks: Vec<&Event> = d.events.iter().filter(|e| e.kind.is_bound_check()).collect();
    let origins: Vec<&Event> = d
        .events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::OriginLoad | EventKind::OriginCall))
        .collect();
    let walk_end = d.events.iter().find(|e| e.kind == EventKind::WalkEnd);

    if d.error == ErrorKind::NullDeref {
        let mut context = Vec::new();
        for o in &origins {
            if o.kind == EventKind::OriginCall && o.loc.line != d.use_loc.line {
                context.push((
                    o.loc,
                    "this lookup returns NULL when the key is absent".to_string(),
                ));
            }
        }
        return Msg {
            title: "possibly-NULL pointer is dereferenced without a check".to_string(),
            primary: (d.use_loc, "dereferenced here".to_string()),
            context,
            decl: None,
            help: Some("check the result before use: `if (!v) return 0;`".to_string()),
        };
    }

    if checks.is_empty() {
        let constraint = match (&d.mem_arg, &enrich.stack_var) {
            (Some(MemArg::Stack { .. }), Some(v)) => Some((
                format!(
                    ", but the destination `{}` holds only {} bytes",
                    v.name,
                    v.size.unwrap_or(0)
                ),
                Some(format!(
                    "bound it before the call: `if (size > sizeof({})) return 0;`",
                    v.name
                )),
            )),
            (Some(MemArg::Stack { off }), None) => Some((
                format!(
                    ", but the destination is a stack region of at most {} bytes",
                    -off
                ),
                None,
            )),
            (Some(MemArg::MapValue { size, .. }), _) => Some((
                format!(", but the destination map value is {} bytes", size),
                None,
            )),
            (Some(MemArg::Mem { size }), _) => {
                Some((format!(", but the destination is {} bytes", size), None))
            }
            _ => None,
        };
        let (constraint, help) = constraint.unwrap_or_default();
        let title = if walk_end.is_some() {
            format!(
                "value used as index/size can be as large as {}{}; no check in this function bounds it",
                d.umax, constraint
            )
        } else {
            format!(
                "value used as index/size can be as large as {}{} and is never bounds-checked",
                d.umax, constraint
            )
        };
        let mut context = Vec::new();
        if let Some(load) = origins.iter().rev().find(|o| o.kind == EventKind::OriginLoad) {
            if load.loc.line != d.use_loc.line {
                context.push((load.loc, "loaded here, unchecked".to_string()));
            }
        }
        if let Some(w) = walk_end {
            context.push((
                w.loc,
                "the value flows through this call; cross-call provenance is not tracked yet"
                    .to_string(),
            ));
        }
        return Msg {
            title,
            primary: (d.use_loc, "used here".to_string()),
            context,
            decl: enrich.stack_var.as_ref().and_then(var_decl_note),
            help,
        };
    }

    let check = checks.last().unwrap();
    match d.access {
        Some(Access::MapValue { value_size, off, size }) if d.umax > 0 => {
            let excess = (off + size) as i64 - value_size as i64;
            let safe_max = d.umax as i64 - excess;
            Msg {
                title: format!(
                    "access reaches byte {} of a {}-byte value",
                    off + size,
                    value_size
                ),
                primary: (
                    d.use_loc,
                    format!(
                        "index can be up to {} here; {} is the largest safe value",
                        d.umax, safe_max
                    ),
                ),
                context: vec![(
                    check.loc,
                    match quoted_cmp(check) {
                        Some(cmp) => format!(
                            "your {} allows {} too many; the bound must stop at {}",
                            cmp, excess, safe_max
                        ),
                        None => format!("this bound allows {} too many", excess),
                    },
                )],
                decl: enrich.member.as_ref().and_then(decl_note),
                help: None,
            }
        }
        Some(Access::MapValue { value_size, off, size }) => {
            let idx = off / size;
            let n = value_size / size;
            let iters = if check.cnt > 1 {
                format!(" after {} iterations", check.cnt)
            } else {
                String::new()
            };
            Msg {
                title: format!(
                    "access to element {} of a {}-element array (valid: 0..={})",
                    idx,
                    n,
                    n - 1
                ),
                primary: (
                    d.use_loc,
                    format!("fails when the index reaches {}", idx),
                ),
                context: vec![(
                    check.loc,
                    format!(
                        "this condition lets the index reach {}{}; it must stop at {}",
                        idx,
                        iters,
                        n - 1
                    ),
                )],
                decl: enrich.member.as_ref().and_then(decl_note),
                help: None,
            }
        }
        Some(Access::Stack { off, size }) => {
            let (what, valid_max) = match &enrich.stack_var {
                Some(v) => {
                    let n = v.size.unwrap_or(0);
                    (
                        format!("the end of `{}` ({} bytes)", v.name, n),
                        n.saturating_sub(1) as i64,
                    )
                }
                None => (
                    "the end of the stack frame".to_string(),
                    -(off as i64) - size as i64,
                ),
            };
            Msg {
                title: format!(
                    "stack buffer access can reach index {}, past {}",
                    d.umax, what
                ),
                primary: (
                    d.use_loc,
                    format!(
                        "index can be up to {} here; {} is the largest valid index",
                        d.umax, valid_max
                    ),
                ),
                context: vec![(
                    check.loc,
                    match quoted_cmp(check) {
                        Some(cmp) => format!(
                            "the only bound comes from your {}; it must stop at {}",
                            cmp, valid_max
                        ),
                        None => "the only bound on the index comes from here".to_string(),
                    },
                )],
                decl: enrich.stack_var.as_ref().and_then(var_decl_note),
                help: None,
            }
        }
        None => Msg {
            title: format!(
                "value can be as large as {} here, which the verifier rejected",
                d.umax
            ),
            primary: (d.use_loc, "used here".to_string()),
            context: checks
                .iter()
                .map(|c| (c.loc, "constrained here".to_string()))
                .collect(),
            decl: None,
            help: None,
        },
    }
}

/// Byte range of `name` on the given source line, for declaration spans
/// where only a line number is known.
fn name_span_on_line(source: &str, line: u32, name: &str) -> Option<std::ops::Range<usize>> {
    if line == 0 {
        return None;
    }
    let mut offset = 0;
    for (i, l) in source.split_inclusive('\n').enumerate() {
        if i + 1 == line as usize {
            let col = l.find(name)?;
            return Some(offset + col..offset + col + name.len());
        }
        offset += l.len();
    }
    None
}

pub fn render(d: &VerifierDiagnostic, source: &str, enrich: &Enrichment) -> String {
    let msg = build_msg(d, enrich);

    let mut snippet = Snippet::source(source).path("<stdin>").fold(true);
    if let Some(range) = span_at(source, msg.primary.0) {
        snippet = snippet.annotation(
            AnnotationKind::Primary
                .span(range)
                .label(&msg.primary.1),
        );
    }
    for (loc, label) in &msg.context {
        if let Some(range) = span_at(source, *loc) {
            snippet = snippet.annotation(AnnotationKind::Context.span(range).label(label));
        }
    }
    if let Some((line, name, label)) = &msg.decl {
        if let Some(range) = name_span_on_line(source, *line, name) {
            snippet = snippet.annotation(AnnotationKind::Context.span(range).label(label));
        }
    }

    let mut report = vec![Level::ERROR.primary_title(&msg.title).element(snippet)];
    if let Some(help) = &msg.help {
        report.push(Group::with_title(Level::HELP.secondary_title(help)));
    }
    Renderer::plain().render(&report).to_string()
}
