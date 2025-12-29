import type { WorkerRequest, WorkerResponse } from "../types/worker";
import TccWorker from "../workers/tcc-worker.ts?worker";

export class TccWorkerClient {
  private worker: Worker;
  private startTime = 0;
  private count = 0;
  private total = 0;

  constructor(
    private onReady: () => void,
    private onStdout: (text: string) => void,
    private onStderr: (text: string) => void,
    private onResult: (
      result: number,
      typeInfo: string | null,
      timing: { time: number; avg: number }
    ) => void,
    private onError: (error: string) => void
  ) {
    this.worker = new TccWorker();
    this.setupListeners();
  }

  private setupListeners() {
    this.worker.onmessage = (e: MessageEvent<WorkerResponse>) => {
      const { type } = e.data;

      switch (type) {
        case "ready":
          this.onReady();
          break;
        case "stdout":
          this.onStdout(e.data.text);
          break;
        case "stderr":
          this.onStderr(e.data.text);
          break;
        case "result":
          this.count++;
          const end = performance.now();
          this.total += end - this.startTime;
          const timing = {
            time: end - this.startTime,
            avg: this.total / this.count,
          };
          this.onResult(e.data.result, e.data.typeInfo, timing);
          break;
        default:
          console.log("Unknown message from worker:", e.data);
      }
    };

    this.worker.onerror = (e) => {
      this.onError(e.message);
    };
  }

  public checkSyntax(code: string, withTypeInfo = false) {
    this.startTime = performance.now();
    this.worker.postMessage({
      type: "typecheck",
      code,
      withTypeInfo,
    } as WorkerRequest);
  }

  public terminate() {
    this.worker.terminate();
  }
}
