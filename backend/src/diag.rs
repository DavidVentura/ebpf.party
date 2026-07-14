use crate::dwarf::{self, DwarfDebugInfo, MemberHit, StackVar};
use annotate_snippets::{AnnotationKind, Group, Level, Renderer, Snippet};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ErrorKind {
    NullDeref,
    NullArg,
    ArgType,
    NotConst,
    ScalarDeref,
    OobPtrArith,
    Unbounded,
    OutOfRange,
    StackOob,
    StackAccessSize,
    ZeroSize,
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

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Loc {
    pub line: u32,
    pub col: u32,
}

impl Loc {
    fn known(&self) -> bool {
        self.line != 0
    }
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
    Stack { off: i32, size: u32, write: bool },
}

/// The memory argument a rejected helper size argument was paired with.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase", tag = "kind")]
pub enum MemArg {
    Stack { off: i64 },
    MapValue { size: u32, map: Option<String> },
    Mem { size: u32 },
}

/// A helper/kfunc argument whose register type does not match what the call
/// accepts (`R2 type=ctx expected=fp, map_key, ...`). The verifier names the
/// actual type and the accepted set.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ArgType {
    pub actual: String,
    pub expected: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct VerifierDiagnostic {
    pub error: ErrorKind,
    pub reg: u8,
    pub umin: u64,
    pub umax: u64,
    pub smin: i64,
    pub smax: i64,
    pub off: i64,
    pub map: Option<String>,
    pub mem_arg: Option<MemArg>,
    pub arg_type: Option<ArgType>,
    pub helper: Option<String>,
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

/// The kernel prints `?` when it has no line_info for an instruction (common
/// when libbpf strips it); such locs are backfilled host-side from DWARF.
fn parse_loc(s: &str) -> Loc {
    let mut it = s.rsplitn(3, ':');
    let col = it.next().and_then(|c| c.parse().ok());
    let line = it.next().and_then(|l| l.parse().ok());
    match (line, col) {
        (Some(line), Some(col)) => Loc { line, col },
        _ => Loc::default(),
    }
}

fn parse_reg(s: &str) -> Option<u8> {
    s.strip_prefix('r')?.parse().ok()
}

fn classify_error(line: &str) -> Option<ErrorKind> {
    if !line.starts_with('R')
        && !line.starts_with("invalid")
        && !line.starts_with("value ")
        && !line.starts_with("math ")
    {
        return None;
    }
    if line.contains("invalid mem access 'map_value_or_null'") {
        return Some(ErrorKind::NullDeref);
    }
    // Dereferencing a non-pointer, e.g. a raw register value read from
    // pt_regs (`(struct sock *)PT_REGS_PARM1(ctx)`) treated as a pointer.
    if line.contains("invalid mem access 'scalar'") {
        return Some(ErrorKind::ScalarDeref);
    }
    // An unchecked scalar added to a pointer takes it out of bounds, e.g.
    // `&req[auth_pos]` where auth_pos is an unbounded/negative return value.
    if line.contains("pointer be out of bounds")
        || (line.contains("math between") && line.contains("unbounded min value"))
    {
        return Some(ErrorKind::OobPtrArith);
    }
    // A maybe-NULL pointer passed to a helper that needs a valid one,
    // e.g. `R1 type=map_value_or_null expected=fp, pkt, ...`. Same root
    // cause as NullDeref: an unchecked map lookup.
    if line.contains("type=") && line.contains("expected=") && line.contains("_or_null") {
        return Some(ErrorKind::NullArg);
    }
    // Any other register-type mismatch on a call argument, e.g. `R2 type=ctx
    // expected=fp, map_key, map_value, mem, ...` (passing the context, a
    // scalar, or the wrong pointer where a helper needs a specific kind).
    if line.starts_with('R') && line.contains("type=") && line.contains("expected=") {
        return Some(ErrorKind::ArgType);
    }
    // A helper argument that must be a compile-time constant (e.g. the size of
    // `bpf_ringbuf_reserve`) fed a runtime value.
    if line.contains("is not a known constant") {
        return Some(ErrorKind::NotConst);
    }
    if line.contains("unbounded memory access") {
        return Some(ErrorKind::Unbounded);
    }
    if line.starts_with("invalid variable-offset") && line.contains("stack") {
        return Some(ErrorKind::StackOob);
    }
    // Fixed-offset helper/direct access whose size overflows a stack slot,
    // e.g. `invalid write to stack R1 off=-16 size=17`.
    if (line.starts_with("invalid write to stack")
        || line.starts_with("invalid read from stack"))
        && line.contains("off=")
        && line.contains("size=")
    {
        return Some(ErrorKind::StackAccessSize);
    }
    if line.contains("invalid zero-sized read") {
        return Some(ErrorKind::ZeroSize);
    }
    if line.contains("value is outside of the allowed memory range") {
        return Some(ErrorKind::OutOfRange);
    }
    if line.contains("min value is negative") {
        return Some(ErrorKind::NegativeMin);
    }
    None
}

/// The product of analysing a verifier log: a ready-to-display rendering plus,
/// when the failure was a bounds/provenance one, the structured diagnostic.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Diagnosis {
    pub diag: Option<VerifierDiagnostic>,
    pub enrichment: Enrichment,
    pub rendered: String,
}

/// Top-level entry: produce a diagnosis from a verifier log, or None when
/// nothing better than the raw log can be said.
pub fn diagnose(
    log: &str,
    source: &str,
    elf: &[u8],
    info: Option<&DwarfDebugInfo>,
) -> Option<Diagnosis> {
    // A failure inside a global function must be framed as such before any
    // bounds detail: the bounds spans would point the user at a caller-side
    // check, which cannot help a function verified in isolation.
    if let Some(name) = global_fn_failure(log) {
        return Some(Diagnosis {
            diag: parse(log),
            enrichment: Enrichment::default(),
            rendered: render_global_fn(&name, source, elf),
        });
    }
    if let Some(mut d) = parse(log) {
        // Identify the failing program's section once — line info and stack
        // layout are per-program, so everything downstream must be scoped to it.
        let btf = crate::btf::BtfLines::parse(elf);
        let section = btf.as_ref().and_then(|b| {
            let cands: Vec<String> = b.section_names().cloned().collect();
            crate::btf::identify_section(elf, log, &cands)
        });
        backfill_locs(&mut d, btf.as_ref(), section.as_deref());
        let enrichment = enrich(&d, elf, info, section.as_deref());
        let rendered = render(&d, source, &enrichment);
        return Some(Diagnosis {
            diag: Some(d),
            enrichment,
            rendered,
        });
    }
    if let Some(rendered) = render_ctx_access(log, source) {
        return Some(Diagnosis {
            diag: None,
            enrichment: Enrichment::default(),
            rendered,
        });
    }
    None
}

/// Fill in any locations the kernel reported as `?` (libbpf stripped its
/// line_info) from the object's own `.BTF.ext`, resolved against the *failing*
/// program's section — critical for multi-program objects, where every
/// `SEC()` has its own instruction offsets starting at 0.
fn backfill_locs(
    d: &mut VerifierDiagnostic,
    btf: Option<&crate::btf::BtfLines>,
    section: Option<&str>,
) {
    let (Some(btf), Some(section)) = (btf, section) else {
        return;
    };
    if !d.use_loc.known() {
        if let Some((line, col)) = btf.resolve(section, d.use_insn) {
            d.use_loc = Loc { line, col };
        }
    }
    for e in &mut d.events {
        if !e.loc.known() {
            if let Some((line, col)) = btf.resolve(section, e.insn) {
                e.loc = Loc { line, col };
            }
        }
    }
}

/// The verifier prints `Validating <name>() func#N...` only when a global
/// (non-static) function fails its *isolated* validation — a passing one
/// leaves no marker, and a caller trusting one prints `Func#N (...) is global
/// and assumed valid` instead. So this marker uniquely identifies the
/// global-function-verified-in-isolation case.
fn global_fn_failure(log: &str) -> Option<String> {
    let mut name = None;
    for line in log.lines() {
        if let Some(rest) = line.strip_prefix("Validating ") {
            if let Some(paren) = rest.find("()") {
                name = Some(rest[..paren].to_string());
            }
        }
    }
    name
}

fn render_global_fn(name: &str, source: &str, elf: &[u8]) -> String {
    let title = format!(
        "`{}` is a global (non-static) function, verified on its own",
        name
    );
    let help = format!(
        "the verifier checks global functions with unconstrained arguments, so a \
         check in the caller does not apply here — mark `{}` `static` (it is then \
         verified together with its caller), or validate its arguments inside the body",
        name
    );

    let span = dwarf::function_decl_line(elf, name)
        .and_then(|line| name_span_on_line(source, line, name));
    let title_group = match span {
        Some(range) => Level::ERROR.primary_title(&title).element(
            Snippet::source(source)

                .fold(true)
                .annotation(
                    AnnotationKind::Primary
                        .span(range)
                        .label("verified in isolation"),
                ),
        ),
        None => Group::with_title(Level::ERROR.primary_title(&title)),
    };
    let report = vec![
        title_group,
        Group::with_title(Level::HELP.secondary_title(&help)),
    ];
    Renderer::plain().render(&report).to_string()
}

/// Context-access failures are offset-shaped, not value-shaped, so they have
/// no DIAG1. The raw log carries the source line via the verifier's own
/// linfo annotation immediately above the error.
fn render_ctx_access(log: &str, source: &str) -> Option<String> {
    let lines: Vec<&str> = log.lines().collect();
    let err_idx = lines
        .iter()
        .position(|l| l.starts_with("invalid bpf_context access"))?;
    let err = lines[err_idx];
    let (off, size) = {
        let mut off = None;
        let mut size = None;
        for tok in err.split_whitespace() {
            if let Some(v) = kv(tok, "off") {
                off = v.parse::<i64>().ok();
            } else if let Some(v) = kv(tok, "size") {
                size = v.parse::<u32>().ok();
            }
        }
        (off?, size)
    };
    // The nearest preceding "; ... @ file:line" annotation locates the access.
    let loc = lines[..err_idx].iter().rev().find_map(|l| {
        let at = l.rfind(" @ ")?;
        let tail = &l[at + 3..];
        let (_file, lc) = tail.rsplit_once(':')?;
        lc.parse::<u32>().ok().map(|line| line)
    })?;

    let title = match size {
        Some(sz) => format!(
            "access at offset {} (size {}) is not a valid field of the program context",
            off, sz
        ),
        None => format!(
            "access at offset {} is not a valid field of the program context",
            off
        ),
    };
    let help = "the context layout is fixed by the program type; access only its \
                declared fields (e.g. `ctx->args[i]` within range for tracepoints)";

    let snippet = Snippet::source(source)

        .fold(true)
        .line_start(1)
        .annotation(
            AnnotationKind::Primary
                .span(line_span(source, loc))
                .label("invalid context access"),
        );
    let report = vec![
        Level::ERROR.primary_title(&title).element(snippet),
        Group::with_title(Level::HELP.secondary_title(help)),
    ];
    Some(Renderer::plain().render(&report).to_string())
}

/// Byte range covering the non-whitespace content of a source line.
fn line_span(source: &str, line: u32) -> std::ops::Range<usize> {
    let mut offset = 0;
    for (i, l) in source.split_inclusive('\n').enumerate() {
        if i + 1 == line as usize {
            let start = l.len() - l.trim_start().len();
            let end = l.trim_end().len();
            return offset + start..offset + end.max(start + 1);
        }
        offset += l.len();
    }
    offset..offset + 1
}

/// Extracts the structured diagnostic from a verifier log carrying a DIAG1
/// trailer. Returns None when the log has no (or a malformed) trailer; the
/// raw log is the only output in that case.
pub fn parse(log: &str) -> Option<VerifierDiagnostic> {
    let mut error = None;
    let mut access = None;
    let mut arg_actual = None;
    let mut arg_expected: Vec<String> = Vec::new();
    let mut calls: Vec<(u32, String)> = Vec::new();
    let mut head: Option<VerifierDiagnostic> = None;
    let mut events = Vec::new();

    for line in log.lines() {
        if let Some(kind) = classify_error(line) {
            error = Some(kind);
        }
        // `R2 type=ctx expected=fp, map_key, map_value, mem, ...`: the actual
        // type sits between `type=` and ` expected=`; the accepted set is the
        // comma list after it (kernel truncates names, e.g. `trusted_ptr_`).
        if line.starts_with('R')
            && !line.contains("_or_null")
            && let (Some(ts), Some(es)) = (line.find(" type="), line.find(" expected="))
        {
            arg_actual = Some(line[ts + 6..es].trim().to_string());
            arg_expected = line[es + 10..]
                .split(',')
                .map(|s| s.trim().trim_end_matches('_').to_string())
                .filter(|s| !s.is_empty())
                .collect();
        }
        // Disassembly of a helper call, `N: (85) call bpf_foo#K`, so the
        // failing call site can be named from its instruction index.
        if let Some((num, rest)) = line.split_once(": (85) call ") {
            if let Ok(insn) = num.trim().parse::<u32>() {
                let helper = rest.split(['#', ' ']).next().unwrap_or("").to_string();
                if !helper.is_empty() {
                    calls.push((insn, helper));
                }
            }
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
        if (line.starts_with("invalid variable-offset") && line.contains("stack"))
            || line.starts_with("invalid write to stack")
            || line.starts_with("invalid read from stack")
        {
            let mut off = None;
            let mut size = None;
            for tok in line.split_whitespace() {
                if let Some(v) = kv(tok, "off") {
                    off = v.parse().ok();
                } else if let Some(v) = kv(tok, "size") {
                    size = v.parse().ok();
                }
            }
            if let (Some(off), Some(size)) = (off, size) {
                access = Some(Access::Stack {
                    off,
                    size,
                    write: line.contains("write to"),
                });
            }
        }
        if let Some(rest) = line.strip_prefix("DIAG1 ") {
            let mut reg = None;
            let mut umin = None;
            let mut umax = None;
            let mut off = None;
            let mut use_insn = None;
            let mut use_loc = Loc::default();
            let mut map = None;
            let mut mem_kind = None;
            let mut mem_off = None;
            let mut mem_size = None;
            let mut mem_map = None;
            let mut smin = None;
            let mut smax = None;
            for tok in rest.split_whitespace() {
                if let Some(v) = kv(tok, "reg") {
                    reg = v.parse().ok();
                } else if let Some(v) = kv(tok, "umin") {
                    umin = v.parse().ok();
                } else if let Some(v) = kv(tok, "umax") {
                    umax = v.parse().ok();
                } else if let Some(v) = kv(tok, "smin") {
                    smin = v.parse().ok();
                } else if let Some(v) = kv(tok, "smax") {
                    smax = v.parse().ok();
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
            let umax = umax?;
            let use_insn = use_insn?;
            let arg_type = arg_actual.take().map(|actual| ArgType {
                actual,
                expected: std::mem::take(&mut arg_expected),
            });
            let helper = calls
                .iter()
                .find(|(i, _)| *i == use_insn)
                .map(|(_, h)| h.clone());
            head = Some(VerifierDiagnostic {
                error: error?,
                reg: reg?,
                umin: umin?,
                umax,
                smin: smin.unwrap_or(0),
                smax: smax.unwrap_or(umax as i64),
                off: off?,
                map,
                mem_arg,
                arg_type,
                helper,
                use_insn,
                use_loc,
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
            let mut loc = Loc::default();
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
                loc,
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
pub fn enrich(
    d: &VerifierDiagnostic,
    elf: &[u8],
    info: Option<&DwarfDebugInfo>,
    section: Option<&str>,
) -> Enrichment {
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
        e.stack_var = match_stack_var(info, off, section);
    }
    e
}

/// DWARF stack offsets count from the frame's low end; the verifier's are
/// fp-relative. Reconcile via the frame size and require a unique match.
/// Scoped to the failing program's section when known (multi-program objects
/// have independent frame layouts per program).
fn match_stack_var(info: &DwarfDebugInfo, fp_off: i64, section: Option<&str>) -> Option<StackVar> {
    let mut hit = None;
    for f in &info.functions {
        if let Some(section) = section {
            if f.section_name != section {
                continue;
            }
        }
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

struct Span {
    loc: Loc,
    label: String,
    /// Mark the whole source line rather than the token at the column. Used
    /// when line_info can't isolate the relevant sub-expression (a call
    /// argument, a loop/if condition).
    whole_line: bool,
}

impl Span {
    fn token(loc: Loc, label: impl Into<String>) -> Span {
        Span { loc, label: label.into(), whole_line: false }
    }
    fn line(loc: Loc, label: impl Into<String>) -> Span {
        Span { loc, label: label.into(), whole_line: true }
    }
}

struct Msg {
    title: String,
    primary: Span,
    context: Vec<Span>,
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

/// Plain-language name for a verifier register type. The raw tokens (`ctx`,
/// `fp`, `map_value`, ...) mean nothing to a user; this is what we show
/// instead. Unknown types fall back to the raw token in backticks.
fn humanize_reg_type(t: &str) -> String {
    match t {
        "ctx" => "the program context".to_string(),
        "scalar" => "a plain integer".to_string(),
        "fp" => "a stack pointer".to_string(),
        "map_value" => "a pointer into a map value".to_string(),
        "map_ptr" => "a map".to_string(),
        "pkt" => "a pointer into the packet".to_string(),
        other => format!("`{}`", other),
    }
}

fn build_msg(d: &VerifierDiagnostic, enrich: &Enrichment) -> Msg {
    let checks: Vec<&Event> = d.events.iter().filter(|e| e.kind.is_bound_check()).collect();
    let origins: Vec<&Event> = d
        .events
        .iter()
        .filter(|e| matches!(e.kind, EventKind::OriginLoad | EventKind::OriginCall))
        .collect();
    let walk_end = d.events.iter().find(|e| e.kind == EventKind::WalkEnd);

    if d.error == ErrorKind::NullDeref || d.error == ErrorKind::NullArg {
        let mut context = Vec::new();
        for o in &origins {
            if o.kind == EventKind::OriginCall && o.loc.line != d.use_loc.line {
                context.push(Span::token(
                    o.loc,
                    "this lookup returns NULL when the key is absent",
                ));
            }
        }
        let (title, primary) = if d.error == ErrorKind::NullArg {
            (
                "possibly-NULL pointer passed to a call that needs a valid pointer",
                "this pointer may be NULL",
            )
        } else {
            (
                "possibly-NULL pointer is dereferenced without a check",
                "dereferenced here",
            )
        };
        return Msg {
            title: title.to_string(),
            primary: Span::token(d.use_loc, primary),
            context,
            decl: None,
            help: Some("check the result before use: `if (!v) return 0;`".to_string()),
        };
    }

    if d.error == ErrorKind::ScalarDeref {
        let mut context = Vec::new();
        if let Some(o) = origins.iter().find(|o| o.loc.line != d.use_loc.line) {
            context.push(Span::token(o.loc, "the address comes from here"));
        }
        return Msg {
            title: "dereferencing a value the verifier treats as a plain integer, not a pointer"
                .to_string(),
            primary: Span::token(d.use_loc, "not a valid pointer here"),
            context,
            decl: None,
            help: Some(
                "a raw kernel address (e.g. from `PT_REGS_PARM*`) is untrusted — read through it \
                 with `bpf_probe_read_kernel()` or `BPF_CORE_READ()`"
                    .to_string(),
            ),
        };
    }

    if d.error == ErrorKind::ZeroSize {
        // Flagged specifically because umin==0. Keep the message to that one
        // fact; an out-of-range upper end is a separate error the user will
        // see next, and overloading this one is confusing.
        return Msg {
            title: "the size passed here can be zero, which this helper rejects".to_string(),
            primary: Span::line(d.use_loc, "this size must not be zero"),
            context: Vec::new(),
            decl: None,
            help: Some("ensure it is non-zero before the call".to_string()),
        };
    }

    if let (ErrorKind::StackAccessSize, Some(Access::Stack { size, write, .. })) =
        (d.error, d.access)
    {
        let verb = if write { "writes" } else { "reads" };
        let (title, help) = match &enrich.stack_var {
            Some(v) => {
                let cap = v.size.unwrap_or(0);
                (
                    format!(
                        "this access {} {} bytes into `{}`, which holds only {}",
                        verb, size, v.name, cap
                    ),
                    Some(format!("pass a size that fits: `sizeof({})` is {}", v.name, cap)),
                )
            }
            None => (
                format!("this access {} {} bytes, past the end of the stack buffer", verb, size),
                None,
            ),
        };
        return Msg {
            title,
            primary: Span::line(d.use_loc, format!("{} {} bytes here", verb, size)),
            context: Vec::new(),
            decl: enrich.stack_var.as_ref().and_then(var_decl_note),
            help,
        };
    }

    if d.error == ErrorKind::ArgType {
        let actual = d.arg_type.as_ref().map(|a| a.actual.as_str()).unwrap_or("");
        let title = match &d.helper {
            Some(h) => format!("wrong type for argument {} of `{}`", d.reg, h),
            None => format!("wrong type for argument {}", d.reg),
        };
        // The verifier's `expected=` list is a union of pointer kinds in
        // kernel spelling (fp, pkt, map_key, ...) — useless to a user. Say
        // plainly that a pointer is wanted for the cases that reach here
        // (context / plain integer), and lean on the help for the concrete fix.
        let human = humanize_reg_type(actual);
        let primary_label = match actual {
            "ctx" | "scalar" => format!("this is {}, but a pointer is expected here", human),
            _ => format!("this is {}, which is not the type expected here", human),
        };
        let mut context = Vec::new();
        if let Some(o) = origins.iter().find(|o| o.loc.line != d.use_loc.line) {
            context.push(Span::token(o.loc, "the value comes from here"));
        }
        return Msg {
            title,
            primary: Span::token(d.use_loc, primary_label),
            context,
            decl: None,
            help: None,
        };
    }

    if d.error == ErrorKind::NotConst {
        let title = match &d.helper {
            Some(h) => format!("`{}` needs a compile-time-constant argument here", h),
            None => "this argument must be a compile-time constant".to_string(),
        };
        let mut context = Vec::new();
        if let Some(o) = origins.iter().find(|o| o.loc.line != d.use_loc.line) {
            context.push(Span::token(o.loc, "this is a runtime-dependent value"));
        }
        let help = match d.helper.as_deref() {
            Some("bpf_ringbuf_reserve") => {
                "reserve a fixed maximum, e.g. `bpf_ringbuf_reserve(&rb, sizeof(struct event), 0)`"
            }
            _ => "use a literal or an expression the compiler can fold to a constant",
        };
        return Msg {
            title,
            primary: Span::token(
                d.use_loc,
                "this call requires a constant, but the argument is runtime-dependent",
            ),
            context,
            decl: None,
            help: Some(help.to_string()),
        };
    }

    // Everything else in the bounds family — out-of-range index, unbounded
    // index/size, variable-offset stack, out-of-bounds pointer arithmetic —
    // shares one "the value's range exceeds the buffer" rendering.
    oob_msg(d, enrich, &checks, &origins, walk_end)
}

/// Uniform rendering for the out-of-bounds family. Two framings: an *index*
/// access (compare the value's index range to the buffer's valid index range)
/// and a *size* argument (compare the value's range to the destination's byte
/// size). The distinguishing note is whether the value was "narrowed" (a
/// check exists but is too loose) or "never narrowed".
enum Framing {
    /// Element access; carries the largest valid index (None if buffer size
    /// is unknown).
    Index(Option<i64>),
    /// Helper size argument; carries the destination name and byte capacity.
    Size(Option<String>, u64),
}

/// Render the well-known signed/unsigned limits symbolically — `INT32_MAX`
/// reads better than `2147483647` and makes "this is the type's whole range"
/// obvious.
fn fmt_bound(v: i64) -> String {
    match v {
        -2147483648 => "INT32_MIN".to_string(),
        2147483647 => "INT32_MAX".to_string(),
        4294967295 => "UINT32_MAX".to_string(),
        i64::MIN => "INT64_MIN".to_string(),
        i64::MAX => "INT64_MAX".to_string(),
        _ => v.to_string(),
    }
}

fn oob_msg(
    d: &VerifierDiagnostic,
    enrich: &Enrichment,
    checks: &[&Event],
    origins: &[&Event],
    walk_end: Option<&Event>,
) -> Msg {
    let check = checks.last();
    let elem = match d.access {
        Some(Access::MapValue { size, .. }) | Some(Access::Stack { size, .. }) => size.max(1) as i64,
        _ => 1,
    };

    // Per-error-kind extraction: which framing, and the buffer's valid extent.
    let framing = if let Some(mem) = &d.mem_arg {
        match mem {
            MemArg::Stack { off } => Framing::Size(
                enrich.stack_var.as_ref().map(|v| v.name.clone()),
                enrich
                    .stack_var
                    .as_ref()
                    .and_then(|v| v.size)
                    .unwrap_or((-off).max(0) as u64),
            ),
            MemArg::MapValue { size, map } => Framing::Size(map.clone(), *size as u64),
            MemArg::Mem { size } => Framing::Size(None, *size as u64),
        }
    } else {
        let valid_max = enrich
            .member
            .as_ref()
            .and_then(|m| m.size)
            .map(|s| (s as i64 / elem) - 1)
            .or_else(|| {
                enrich
                    .stack_var
                    .as_ref()
                    .and_then(|v| v.size)
                    .map(|s| (s as i64 / elem) - 1)
            })
            .or_else(|| match d.access {
                Some(Access::MapValue { value_size, size, .. }) => {
                    Some((value_size as i64 / size.max(1) as i64) - 1)
                }
                _ => None,
            });
        Framing::Index(valid_max)
    };

    // The value's range, in index units (shared). Signed bounds when it can be
    // negative (a `bpf_strstr` result); otherwise the unsigned max, or — for a
    // strength-reduced loop where umax is 0 — the loop bound in the check.
    let scale = |b: i64| if elem > 1 && b % elem == 0 { b / elem } else { b };
    let (lo, hi) = if d.smin < 0 {
        (scale(d.smin), scale(d.smax))
    } else {
        let hi_raw = if d.umax > 0 {
            d.umax.min(i64::MAX as u64) as i64
        } else if let Some(v) = check.and_then(|c| c.val) {
            v as i64
        } else {
            d.off
        };
        (scale(d.umin as i64), scale(hi_raw))
    };
    let range = format!("[{}, {}]", fmt_bound(lo), fmt_bound(hi));

    // The one framing-specific line.
    let primary_label = match &framing {
        Framing::Index(Some(vm)) => format!(
            "index can be {}, while the buffer can be accessed on [0, {}]",
            range,
            fmt_bound(*vm)
        ),
        Framing::Index(None) => {
            format!("index can be {}, and is never narrowed to the buffer", range)
        }
        Framing::Size(Some(n), bytes) => {
            format!("size can be {}, while `{}` holds only {} bytes", range, n, bytes)
        }
        Framing::Size(None, bytes) => {
            format!("size can be {}, larger than the {}-byte destination", range, bytes)
        }
    };

    // Context, help, and Msg are shared across framings.
    // origin → narrow* → use: when narrowed, point at the loosest check;
    // otherwise at where the value came from (load/call/const — the note is
    // the same regardless of origin kind).
    let mut context = Vec::new();
    if let Some(c) = check {
        context.push(Span::line(c.loc, "this narrowing is not strict enough"));
    } else if let Some(o) = origins.iter().rev().find(|o| o.loc.line != d.use_loc.line) {
        context.push(Span::token(o.loc, "the value comes from here and is never narrowed"));
    }
    if let Some(w) = walk_end {
        context.push(Span::token(
            w.loc,
            "the value flows through this call; cross-call provenance is not tracked yet",
        ));
    }

    let help = if lo < 0 {
        Some("narrow it before indexing, e.g. `if (i < 0 || i >= sizeof(buf)) return 0;`".to_string())
    } else if let Framing::Size(Some(n), _) = &framing {
        Some(format!("narrow it first, e.g. `if (size > sizeof({})) return 0;`", n))
    } else {
        None
    };

    // A size argument sits inside a call whose column line_info can't isolate,
    // so mark the whole statement; a direct index expression keeps its caret.
    let primary = match framing {
        Framing::Size(..) => Span::line(d.use_loc, primary_label),
        Framing::Index(..) => Span::token(d.use_loc, primary_label),
    };

    Msg {
        title: "possible out-of-bounds buffer access".to_string(),
        primary,
        context,
        decl: None,
        help,
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

    // A span marks either the token at its column or the whole line, decided
    // per-span (call arguments and if/loop conditions can't be isolated from
    // line_info, so those are marked whole-line).
    let range_of = |sp: &Span| -> Option<std::ops::Range<usize>> {
        if sp.whole_line && sp.loc.line != 0 {
            Some(line_span(source, sp.loc.line))
        } else {
            span_at(source, sp.loc)
        }
    };

    let mut snippet = Snippet::source(source).fold(true);
    if let Some(range) = range_of(&msg.primary) {
        snippet = snippet.annotation(
            AnnotationKind::Primary
                .span(range)
                .label(&msg.primary.label),
        );
    }
    for sp in &msg.context {
        if let Some(range) = range_of(sp) {
            snippet = snippet.annotation(AnnotationKind::Context.span(range).label(&sp.label));
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
