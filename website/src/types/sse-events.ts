export type SSEEvent =
  | { type: "compiling" }
  | { type: "booting" }
  | { type: "booted" }
  | { type: "compileError"; data: string }
  | { type: "executionResult"; data: ExecutionResult };

export type ExecutionResult =
  | { type: "foundProgram"; data: { name: string; section: string } }
  | { type: "foundMap"; data: { name: string } }
  | { type: "noPerfMapsFound" }
  | { type: "noProgramsFound" }
  | { type: "event"; data: number[] }
  | { type: "finished"; data: [] };
