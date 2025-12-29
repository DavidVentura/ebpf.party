import { useEffect, useRef, useState } from "react";
import { TccWorkerClient } from "../lib/tcc-worker-client";
import CodeEditor from "./CodeEditor";
import CompilerOutput from "./CompilerOutput";
import StructSelector from "./StructSelector";
import StructViewer from "./StructViewer";
import type { TypeInfo } from "../types/typeinfo";
import styles from "./App.module.css";

interface AppProps {
  starterCode?: string;
}

export default function App({ starterCode = "" }: AppProps) {
  const [code, setCode] = useState(starterCode);
  const [output, setOutput] = useState("Initializing WASM...");
  const [outputClass, setOutputClass] = useState<"warning" | "error" | "">("");
  const [typeInfo, setTypeInfo] = useState<{ [name: string]: TypeInfo }>({});
  const [selectedStructName, setSelectedStructName] = useState<string | null>(
    null
  );
  const workerRef = useRef<TccWorkerClient | null>(null);
  const hasOutputRef = useRef(false);
  const compilationOutputRef = useRef("");

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
    };
  }, []);

  const handleCodeChange = (newCode: string) => {
    setCode(newCode);
    compilationOutputRef.current = "";
    hasOutputRef.current = false;
    workerRef.current?.checkSyntax(newCode, true);
  };

  const handleSelectStruct = (name: string) => {
    setSelectedStructName(name);
  };

  return (
    <div className={styles.app}>
      <div style={{ flex: 1, display: "flex", flexDirection: "column" }}>
        <CodeEditor code={code} onChange={handleCodeChange} />
      </div>
      {outputClass && (
        <CompilerOutput output={output} outputClass={outputClass} />
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
