export type WorkerRequest = {
  type: 'typecheck';
  code: string;
  withTypeInfo: boolean;
};

export type TccError = {
  filename: string | null;
  lineNum: number;
  isWarning: boolean;
  msg: string;
};

export type WorkerResponse =
  | { type: 'ready' }
  | { type: 'stdout'; text: string }
  | { type: 'stderr'; text: string }
  | { type: 'result'; result: number; typeInfo: string | null; debTypeInfo: string | null; errors: TccError[] };
