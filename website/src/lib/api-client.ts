import type { SSEEvent } from "../types/sse-events";

const API_BASE_URL = import.meta.env.DEV ? "http://localhost:8081" : "";

export function runCode(
  code: string,
  exerciseId: string,
  onEvent: (event: SSEEvent) => void,
  onError: (error: string) => void,
  onComplete: () => void
): () => void {
  const abortController = new AbortController();
  let reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  fetch(`${API_BASE_URL}/run_code/${exerciseId}`, {
    method: "POST",
    headers: {
      "Content-Type": "text/plain",
    },
    body: code,
    signal: abortController.signal,
  })
    .then((response) => {
      if (!response.ok) {
        throw new Error(`HTTP error! status: ${response.status}`);
      }

      if (!response.body) {
        throw new Error("Response body is null");
      }

      reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";

      function processText(text: string) {
        buffer += text;
        const lines = buffer.split("\n");
        buffer = lines.pop() || "";

        for (const line of lines) {
          if (line.startsWith("data: ")) {
            const data = line.slice(6);
            if (data.trim()) {
              const event: SSEEvent = JSON.parse(data);
              onEvent(event);
            }
          }
        }
      }

      function pump(): Promise<void> {
        return reader!.read().then(({ done, value }) => {
          if (done) {
            onComplete();
            return;
          }

          processText(decoder.decode(value, { stream: true }));
          return pump();
        });
      }

      return pump();
    })
    .catch((error) => {
      if (error.name === "AbortError") {
        return;
      }
      onEvent({ type: "requestError", data: error.message });
      onError(error.message);
    });

  return () => {
    abortController.abort();
    reader?.cancel();
  };
}
