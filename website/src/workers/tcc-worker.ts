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

import('../wasm/syntax_check.mjs').then((TCC: any) => {
  return TCC.default({
    print: (text: string) => {
      self.postMessage({ type: 'stdout', text });
    },
    printErr: (text: string) => {
      self.postMessage({ type: 'stderr', text });
    },
    locateFile: (path: string) => {
      if (path.endsWith('.wasm') || path.endsWith('.data')) {
        return '/tcc/' + path;
      }
      return path;
    },
  });
}).then((module: EmscriptenModule) => {
  Module = module;
  self.postMessage({ type: 'ready' });
}).catch((err: Error) => {
  self.postMessage({ type: 'stderr', text: 'Failed to load WASM: ' + err.message });
});

self.onmessage = (e: MessageEvent) => {
  const { type } = e.data;

  switch (type) {
    case 'typecheck': {
      const { code, withTypeInfo } = e.data;

      if (Module.ccall) {
        const result = Module.ccall(
          'check_syntax',
          'number',
          ['string', 'number'],
          [code, withTypeInfo ? 1 : 0]
        );

        let typeInfo: string | null = null;
        if (withTypeInfo && result === 0) {
          const bufPtr = Module.ccall('get_type_info_buffer', 'number', [], []);
          const bufLen = Module.ccall('get_type_info_length', 'number', [], []);

          if (bufPtr && bufLen > 0) {
            typeInfo = Module.UTF8ToString(bufPtr, bufLen);
          }
        }

        self.postMessage({
          type: 'result',
          result,
          typeInfo,
        });
      } else {
        self.postMessage({
          type: 'stderr',
          text: 'Error: Module.ccall is not ready.',
        });
      }
      break;
    }
    default:
      console.log('worker: unhandled message type', type);
  }
};
