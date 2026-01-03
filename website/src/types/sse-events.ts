export type SSEEvent =
  | { type: "compiling" }
  | { type: "booting" }
  | { type: "compileError"; data: string }
  | { type: "requestError"; data: string }
  | { type: "guestMessage"; data: GuestMessage }
  | { type: "stack"; data: { functions: DwarfFunction[] } }
  | { type: "correctAnswer" }
  | { type: "wrongAnswer" }
  | { type: "multipleAnswers" }
  | { type: "noAnswer" };

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
  | { type: "verifierFail"; data: string }
  | { type: "event"; data: number[] }
  | { type: "finished" }
  | { type: "booted" }
  | { type: "crashed" };
