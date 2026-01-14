declare const self: DedicatedWorkerGlobalScope;

interface EmscriptenModule {
  ccall: (
    ident: string,
    returnType: string,
    argTypes: string[],
    args: any[]
  ) => any;
  UTF8ToString: (ptr: number, maxBytesToRead?: number) => string;
}

let Module: EmscriptenModule;

import("../wasm/syntax_check.mjs")
  .then((TCC: any) => {
    return TCC.default({
      print: (text: string) => {
        self.postMessage({ type: "stdout", text });
      },
      printErr: (text: string) => {
        self.postMessage({ type: "stderr", text });
      },
      locateFile: (path: string) => {
        if (path.endsWith(".wasm") || path.endsWith(".data")) {
          return "/tcc/" + path;
        }
        return path;
      },
    });
  })
  .then((module: EmscriptenModule) => {
    Module = module;
    self.postMessage({ type: "ready" });
  })
  .catch((err: Error) => {
    self.postMessage({
      type: "stderr",
      text: "Failed to load WASM: " + err.message,
    });
  });

self.onmessage = (e: MessageEvent) => {
  const { type } = e.data;

  switch (type) {
    case "typecheck": {
      const { code, withTypeInfo } = e.data;

      if (Module.ccall) {
        const result = Module.ccall(
          "check_syntax",
          "number",
          ["string", "number"],
          [code, withTypeInfo ? 1 : 0]
        );

        const errors = [];
        if (result !== 0) {
          const errorCount = Module.ccall("get_error_count", "number", [], []);

          for (let i = 0; i < errorCount; i++) {
            const filenamePtr = Module.ccall(
              "get_error_filename",
              "number",
              ["number"],
              [i]
            );
            const lineNum = Module.ccall(
              "get_error_line_num",
              "number",
              ["number"],
              [i]
            );
            const isWarning = Module.ccall(
              "get_error_is_warning",
              "number",
              ["number"],
              [i]
            );
            const msgPtr = Module.ccall(
              "get_error_msg",
              "number",
              ["number"],
              [i]
            );

            const filename = filenamePtr
              ? Module.UTF8ToString(filenamePtr)
              : null;
            const msg = msgPtr ? Module.UTF8ToString(msgPtr) : "<no message>";
            const errorType = isWarning ? "Warning" : "Error";

            errors.push({
              filename,
              lineNum,
              isWarning: Boolean(isWarning),
              msg,
            });
          }
        }

        let typeInfo: string | null = null;
        let debTypeInfo: string | null = null;
        if (withTypeInfo && result === 0) {
          const bufPtr = Module.ccall("get_type_info_buffer", "number", [], []);
          const bufLen = Module.ccall("get_type_info_length", "number", [], []);

          if (bufPtr && bufLen > 0) {
            typeInfo = Module.UTF8ToString(bufPtr, bufLen);
          }

          const debBufPtr = Module.ccall(
            "get_debug_calls_buffer",
            "number",
            [],
            []
          );
          const debBufLen = Module.ccall(
            "get_debug_calls_length",
            "number",
            [],
            []
          );

          if (debBufPtr && debBufLen > 0) {
            debTypeInfo = Module.UTF8ToString(debBufPtr, debBufLen);
          }
        }

        self.postMessage({
          type: "result",
          result,
          typeInfo,
          debTypeInfo,
          errors,
        });
      } else {
        self.postMessage({
          type: "stderr",
          text: "Error: Module.ccall is not ready.",
        });
      }
      break;
    }
    default:
      console.log("worker: unhandled message type", type);
  }
};
