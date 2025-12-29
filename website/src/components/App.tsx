import { useEffect, useRef, useState } from "react";
import { TccWorkerClient } from "../lib/tcc-worker-client";
import { runCode } from "../lib/api-client";
import CodeEditor from "./CodeEditor";
import CompilerOutput from "./CompilerOutput";
import RunButton from "./RunButton";
import EventViewer from "./EventViewer";
import StructSelector from "./StructSelector";
import StructViewer from "./StructViewer";
import type { TypeInfo } from "../types/typeinfo";
import type { SSEEvent } from "../types/sse-events";
import styles from "./App.module.css";

interface AppProps {
  starterCode?: string;
  exerciseId: string;
}

export default function App({ starterCode, exerciseId }: AppProps) {
  if (!exerciseId) {
    throw new Error("Missing exerciseId");
  }
  if (!starterCode) {
    throw new Error("Missing starterCode");
  }
  const DEBOUNCE_TIME_MS = 200;
  const [code, setCode] = useState(starterCode);
  const [output, setOutput] = useState("Initializing WASM...");
  const [outputClass, setOutputClass] = useState<"warning" | "error" | "">("");
  const [typeInfo, setTypeInfo] = useState<{ [name: string]: TypeInfo }>({});
  const [selectedStructName, setSelectedStructName] = useState<string | null>(
    null
  );
  const [isRunning, setIsRunning] = useState(false);
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const workerRef = useRef<TccWorkerClient | null>(null);
  const hasOutputRef = useRef(false);
  const compilationOutputRef = useRef("");
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const abortRunRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    const worker = new TccWorkerClient(
      () => {
        setOutput("Ready. Target: x86_64 (LP64)\n");
        setOutputClass("");

        if (code.trim()) {
          worker.checkSyntax(code, true);
        }
      },
      (text) => {
        compilationOutputRef.current += text + "\n";
        hasOutputRef.current = true;
      },
      (text) => {
        compilationOutputRef.current += text + "\n";
        hasOutputRef.current = true;
      },
      (result, typeInfoJson, timing) => {
        console.log(`Compiling took ${timing.time}ms`);

        if (typeInfoJson) {
          const parsed: TypeInfo[] = JSON.parse(typeInfoJson);
          const typeInfoObj = parsed.reduce(
            (acc, t) => ({ ...acc, [t.name]: t }),
            {}
          );
          setTypeInfo(typeInfoObj);

          if (parsed.length > 0 && !selectedStructName) {
            setSelectedStructName(parsed[0].name);
          }
        }

        let newOutputClass: "warning" | "error" | "" = "";
        if (result === 0) {
          if (hasOutputRef.current) {
            newOutputClass = "warning";
          }
        } else {
          compilationOutputRef.current += `Syntax Error (Result: ${result})\n`;
          newOutputClass = "error";
        }

        setOutput(compilationOutputRef.current);
        setOutputClass(newOutputClass);
      },
      (error) => {
        compilationOutputRef.current += "Worker Error: " + error + "\n";
        setOutput(compilationOutputRef.current);
        setOutputClass("error");
      }
    );

    workerRef.current = worker;

    return () => {
      worker.terminate();
      abortRunRef.current?.();
    };
  }, []);

  const handleCodeChange = (newCode: string) => {
    setCode(newCode);

    if (debounceTimeoutRef.current) {
      clearTimeout(debounceTimeoutRef.current);
    }

    debounceTimeoutRef.current = setTimeout(() => {
      compilationOutputRef.current = "";
      hasOutputRef.current = false;
      // TODO need to be smarter with type generation
      // maybe figure out how to gen 'task.h' once only
      // then the rest
      workerRef.current?.checkSyntax(newCode, false);
    }, DEBOUNCE_TIME_MS);
  };

  const handleSelectStruct = (name: string) => {
    setSelectedStructName(name);
  };

  const handleRun = () => {
    if (outputClass === "error" || isRunning) return;

    setIsRunning(true);
    setEvents([]);

    const abort = runCode(
      code,
      exerciseId,
      (event) => setEvents((prev) => [...prev, event]),
      (error) => {
        console.error("Run error:", error);
        setIsRunning(false);
      },
      () => setIsRunning(false)
    );

    abortRunRef.current = abort;
  };

  const canRun = outputClass !== "error" && !isRunning;

  return (
    <div className={styles.app}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <CodeEditor
          code={code}
          onChange={handleCodeChange}
          onRun={handleRun}
          canRun={canRun}
        />
        <RunButton
          disabled={outputClass === "error"}
          isRunning={isRunning}
          onRun={handleRun}
        />
      </div>
      {outputClass && (
        <CompilerOutput output={output} outputClass={outputClass} />
      )}
      {events.length > 0 && (
        <EventViewer events={events} isRunning={isRunning} />
      )}
      {Object.keys(typeInfo).length > 0 && (
        <>
          <StructSelector
            structs={typeInfo}
            selectedName={selectedStructName}
            onSelect={handleSelectStruct}
          />
          {selectedStructName && (
            <StructViewer typeInfo={typeInfo[selectedStructName]} />
          )}
        </>
      )}
    </div>
  );
}
