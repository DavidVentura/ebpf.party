export type SSEEvent =
  | { type: "compiling" }
  | { type: "booting" }
  | { type: "booted" }
  | { type: "compileError"; data: string }
  | { type: "guestMessage"; data: GuestMessage };

export type GuestMessage =
  | { type: "foundProgram"; data: { name: string; section: string } }
  | { type: "foundMap"; data: { name: string } }
  | { type: "debugMapNotFound" }
  | { type: "noProgramsFound" }
  | { type: "verifierFail"; data: string }
  | { type: "event"; data: number[] }
  | { type: "finished"; data: [] };
