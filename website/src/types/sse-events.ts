export type SSEEvent =
  | { type: "compiling" }
  | { type: "booting" }
  | { type: "compileError"; data: string }
  | { type: "requestError"; data: string }
  | { type: "guestMessage"; data: GuestMessage }
  | { type: "stack"; data: { functions: DwarfFunction[] } }
  | { type: "verifierDiagnostic"; data: VerifierDiagnostic }
  | { type: "correctAnswer" }
  | { type: "wrongAnswer" }
  | { type: "multipleAnswers" }
  | { type: "noAnswer" };

// Structured verifier diagnostic. `rendered` is the ready-to-display,
// rustc-style annotated snippet; `raw` is the original verifier log kept as a
// fallback when the diagnosis is wrong. `diag` carries the structured spans
// for future editor integration.
export type VerifierDiagnostic = {
  rendered: string;
  raw: string;
  diag: unknown;
  enrichment: unknown;
};

export type DwarfFunction = {
  function_name: string;
  section_name: string;
  stack_vars: Array<{
    name: string;
    type_info: string;
    offset: number;
    size: number;
    is_parameter: boolean;
  }>;
};
export type GuestMessage =
  | { type: "foundProgram"; data: { name: string; section: string } }
  | { type: "foundMap"; data: { name: string } }
  | { type: "debugMapNotFound" }
  | { type: "noProgramsFound" }
  | {
      type: "cantAttachProgram";
      data: { section: string; kind: "noSuchHook" | "denied" | "other" };
    }
  | { type: "verifierFail"; data: string }
  | { type: "event"; data: number[] }
  | { type: "finished" }
  | { type: "booted" }
  | { type: "crashed" };
