import { useEffect, useRef, useState } from "react";
import clsx from "clsx";
import { TccWorkerClient } from "../lib/tcc-worker-client";
import StructViewer from "./StructViewer";
import type { TypeInfo } from "../types/typeinfo";
import styles from "./CodeEditorWithViewer.module.css";

interface CodeEditorWithViewerProps {
  starterCode?: string;
}

export default function CodeEditorWithViewer({
  starterCode = "",
}: CodeEditorWithViewerProps) {
  const textareaRef = useRef<HTMLTextAreaElement>(null);
  const [output, setOutput] = useState("Initializing WASM...");
  const [outputClass, setOutputClass] = useState("");
  const [typeInfo, setTypeInfo] = useState<TypeInfo | null>(null);
  const workerRef = useRef<TccWorkerClient | null>(null);

  useEffect(() => {
    if (!textareaRef.current) return;

    const textarea = textareaRef.current;
    const worker = new TccWorkerClient(
      () => {
        textarea.placeholder = "Write your C code here...";
        textarea.disabled = false;
        setOutput("Ready. Target: x86_64 (LP64)\n");

        if (textarea.value.trim()) {
          worker.checkSyntax(textarea.value, true);
        }
      },
      (text) => {
        setOutput((prev) => prev + text + "\n");
      },
      (text) => {
        setOutput((prev) => prev + text + "\n");
      },
      (result, typeInfoJson, timing) => {
        setOutput(
          (prev) =>
            prev +
            `Took ${timing.time.toFixed(2)}ms. Avg ${timing.avg.toFixed(2)}ms\n`
        );

        if (typeInfoJson) {
          const parsed = JSON.parse(typeInfoJson).filter(
            (x) => x.name == "trace_event_raw_sched_process_exec"
          );
          setTypeInfo(parsed[0]);
        }

        if (result === 0) {
          setOutput((prev) => prev + "Syntax OK.\n");
          setOutputClass("success");
        } else {
          setOutput((prev) => prev + `Syntax Error (Result: ${result})\n`);
          setOutputClass("error");
        }
      },
      (error) => {
        setOutput((prev) => prev + "Worker Error: " + error + "\n");
        setOutputClass("error");
      }
    );

    workerRef.current = worker;

    const handleInput = () => {
      setOutput("");
      setOutputClass("");
      worker.checkSyntax(textarea.value, true);
    };

    textarea.addEventListener("input", handleInput);

    return () => {
      textarea.removeEventListener("input", handleInput);
      worker.terminate();
    };
  }, []);

  return (
    <>
      <div className={styles.editor}>
        <textarea
          ref={textareaRef}
          id="code"
          autoComplete="off"
          defaultValue={starterCode}
        />
        <div
          className={clsx(styles.output, outputClass && styles[outputClass])}
        >
          {output}
        </div>
      </div>
      {typeInfo && <StructViewer typeInfo={typeInfo} />}
    </>
  );
}
