export type FuncArg = {
  type: string;
  name: string;
  description: string;
};

export type FuncReturn = {
  type: string;
  description: string | { success: string; error: string };
};

export type FuncDoc = {
  function_name: string;
  description: string;
  args: FuncArg[];
  returns: FuncReturn;
  docsUrl: string;
};
