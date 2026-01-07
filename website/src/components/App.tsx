import { useEffect, useRef, useState } from "react";
import { TccWorkerClient } from "../lib/tcc-worker-client";
import { runCode } from "../lib/api-client";
import { debTypeRegistry } from "../lib/deb-type-registry";
import CodeEditor from "./CodeEditor";
import CompilerOutput from "./CompilerOutput";
import RunButton from "./RunButton";
import EventViewer from "./EventViewer";
import StructViewer from "./StructViewer";
import { Panel, Group, Separator } from "react-resizable-panels";
import type { TypeInfo } from "../types/typeinfo";
import type { DebTypeInfo } from "../types/debtypeinfo";
import type { SSEEvent } from "../types/sse-events";
import styles from "./App.module.css";

interface AppProps {
  starterCode: string;
  exerciseId: string;
  chapterId?: number;
}

export default function App({ starterCode, exerciseId, chapterId }: AppProps) {
  if (!exerciseId) {
    throw new Error("Missing exerciseId");
  }
  if (!starterCode) {
    throw new Error("Missing starterCode");
  }
  const DEBOUNCE_TIME_MS = 200;
  const codeStorageKey = `user-code-${exerciseId}`;

  const getInitialCode = () => {
    if (typeof window === "undefined") return starterCode;
    const savedCode = localStorage.getItem(codeStorageKey);
    return savedCode !== null ? savedCode : starterCode;
  };

  const [code, setCode] = useState(getInitialCode);
  const [output, setOutput] = useState("Initializing WASM...");
  const [outputClass, setOutputClass] = useState<"warning" | "error" | "">("");
  const [typeInfo, setTypeInfo] = useState<{ [name: string]: TypeInfo }>({});
  const [selectedStructName, setSelectedStructName] = useState<string | null>(
    null
  );
  const [isRunning, setIsRunning] = useState(false);
  const [events, setEvents] = useState<SSEEvent[]>([]);
  const [savedLayout, setSavedLayout] = useState<
    { [key: string]: number } | undefined
  >(undefined);
  const [isSettingsOpen, setIsSettingsOpen] = useState(false);
  const [compileAsYouType, setCompileAsYouType] = useState(true);
  const workerRef = useRef<TccWorkerClient | null>(null);
  const hasOutputRef = useRef(false);
  const compilationOutputRef = useRef("");
  const debounceTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const abortRunRef = useRef<(() => void) | null>(null);
  const lastCheckedCodeRef = useRef(getInitialCode());
  const currentCodeRef = useRef(getInitialCode());

  useEffect(() => {
    const worker = new TccWorkerClient(
      () => {
        setOutput("");
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
      (result, typeInfoJson, debTypeInfoJson, timing, errors) => {
        if (typeInfoJson) {
          const parsed: TypeInfo[] = JSON.parse(typeInfoJson);
          const typeInfoObj = parsed.reduce(
            (acc, t) => ({ ...acc, [t.name]: t }),
            {}
          );
          setTypeInfo(typeInfoObj);
        }

        if (debTypeInfoJson) {
          const parsed: DebTypeInfo[] = JSON.parse(debTypeInfoJson);
          debTypeRegistry.set(parsed);
        }

        if (errors.length > 0) {
          errors.forEach((err) => {
            const errorType = err.isWarning ? "Warning" : "Error";
            if (err.filename === "<string>") {
              compilationOutputRef.current += `${errorType} at line ${err.lineNum}: ${err.msg}\n`;
            } else {
              compilationOutputRef.current += `${errorType} at ${
                err.filename || "<unknown>"
              }:${err.lineNum}: ${err.msg}\n`;
            }
          });
        }

        const hasErrors = errors.some((e) => !e.isWarning);
        const hasWarnings = errors.some((e) => e.isWarning);

        let newOutputClass: "warning" | "error" | "" = "";
        if (hasErrors) {
          newOutputClass = "error";
        } else if (hasWarnings || hasOutputRef.current) {
          newOutputClass = "warning";
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

  useEffect(() => {
    const storageKey = `ebpf-party-layout`;
    const saved = localStorage.getItem(storageKey);
    if (saved) {
      setSavedLayout(JSON.parse(saved));
    }

    const compileSettingKey = `ebpf-party-compile-as-you-type`;
    const savedCompileSetting = localStorage.getItem(compileSettingKey);
    if (savedCompileSetting !== null) {
      setCompileAsYouType(savedCompileSetting === "true");
    }
  }, []);

  const performCheck = (code: string) => {
    compilationOutputRef.current = "";
    hasOutputRef.current = false;
    workerRef.current?.checkSyntax(code, false);
    lastCheckedCodeRef.current = code;
  };

  const compileCode = (
    code: string,
    generateTypeBindings: boolean
  ): Promise<{ success: boolean; errors: any[] }> => {
    return new Promise((resolve) => {
      compilationOutputRef.current = "";
      hasOutputRef.current = false;

      const originalOnResult = workerRef.current?.onResult;

      workerRef.current!.onResult = (
        result,
        typeInfoJson,
        debTypeInfoJson,
        timing,
        errors
      ) => {
        if (originalOnResult) {
          originalOnResult(
            result,
            typeInfoJson,
            debTypeInfoJson,
            timing,
            errors
          );
        }

        const hasErrors = errors.some((e) => !e.isWarning);
        resolve({ success: !hasErrors, errors });

        workerRef.current!.onResult = originalOnResult;
      };

      workerRef.current?.checkSyntax(code, generateTypeBindings);
    });
  };

  const handleCodeChange = (newCode: string) => {
    setCode(newCode);
    currentCodeRef.current = newCode;

    if (!compileAsYouType) {
      return;
    }

    if (!debounceTimeoutRef.current) {
      performCheck(newCode);

      debounceTimeoutRef.current = setTimeout(() => {
        if (currentCodeRef.current !== lastCheckedCodeRef.current) {
          performCheck(currentCodeRef.current);
        }
        debounceTimeoutRef.current = null;
      }, DEBOUNCE_TIME_MS);
    }
  };

  const handleSelectStruct = (name: string) => {
    if (typeInfo[name]) {
      setSelectedStructName(name);
    }
  };

  const handleRun = async () => {
    if (isRunning) return;

    localStorage.setItem(codeStorageKey, code);

    const { success } = await compileCode(code, true);

    if (!success) {
      setIsRunning(false);
      return;
    }
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

  const handleDelete = () => {
    localStorage.removeItem(codeStorageKey);
    setCode(starterCode);
    currentCodeRef.current = starterCode;
    lastCheckedCodeRef.current = starterCode;
    performCheck(starterCode);
  };

  const canRun = !isRunning;

  const storageKey = `ebpf-party-layout`;

  const handleLayoutChange = (layout: { [key: string]: number }) => {
    localStorage.setItem(storageKey, JSON.stringify(layout));
  };

  const handleCompileAsYouTypeChange = (checked: boolean) => {
    setCompileAsYouType(checked);
    localStorage.setItem("ebpf-party-compile-as-you-type", String(checked));

    if (checked && currentCodeRef.current !== lastCheckedCodeRef.current) {
      performCheck(currentCodeRef.current);
    }
  };

  return (
    <div className={styles.app}>
      <Group
        orientation="vertical"
        id={storageKey}
        defaultLayout={savedLayout}
        onLayoutChange={handleLayoutChange}
        style={{ height: "100%" }}
      >
        <Panel id="editor-panel" defaultSize="80%" minSize="33%" maxSize="80%">
          <div className={styles.editorPanel}>
            <div className={styles.runButtonHeader}>
              <RunButton
                disabled={!canRun}
                isRunning={isRunning}
                onRun={handleRun}
              />
              <button
                className={styles.settingsButton}
                onClick={() => setIsSettingsOpen(true)}
                title="Settings"
              >
                ⚙️
              </button>
              <button
                className={styles.deleteButton}
                onClick={handleDelete}
                title="Reset to starter code"
              >
                🗑️
              </button>
            </div>
            <div className={styles.editorWrapper}>
              <CodeEditor
                code={code}
                onChange={handleCodeChange}
                onRun={handleRun}
                canRun={canRun}
                onSelectStruct={handleSelectStruct}
              />
            </div>
            {outputClass && (
              <CompilerOutput output={output} outputClass={outputClass} />
            )}
            {Object.keys(typeInfo).length > 0 && selectedStructName && (
              <>
                {/* <StructSelector
                  structs={typeInfo}
                  selectedName={selectedStructName}
                  onSelect={handleSelectStruct}
                /> TODO delete me*/}
                {selectedStructName && (
                  <StructViewer
                    typeInfo={typeInfo[selectedStructName]}
                    onClose={() => setSelectedStructName(null)}
                  />
                )}
              </>
            )}
          </div>
        </Panel>

        <Separator className={styles.resizeHandle} />

        <Panel id="events-panel" defaultSize="20%" minSize="20%">
          {events.length > 0 ? (
            <EventViewer
              events={events}
              isRunning={isRunning}
              onClear={() => setEvents([])}
              typeRegistry={typeInfo}
            />
          ) : (
            <div className={styles.emptyEventsPane}>
              Run your code to see execution events here
            </div>
          )}
        </Panel>
      </Group>

      {isSettingsOpen && (
        <div
          className={styles.modalOverlay}
          onClick={() => setIsSettingsOpen(false)}
        >
          <div
            className={styles.modalContent}
            onClick={(e) => e.stopPropagation()}
          >
            <div className={styles.modalHeader}>
              <h2>Settings</h2>
              <button
                className={styles.modalCloseButton}
                onClick={() => setIsSettingsOpen(false)}
                title="Close"
              >
                ✕
              </button>
            </div>
            <div className={styles.modalBody}>
              <label className={styles.settingItem}>
                <input
                  type="checkbox"
                  checked={compileAsYouType}
                  onChange={(e) =>
                    handleCompileAsYouTypeChange(e.target.checked)
                  }
                />
                <span>Compile as you type</span>
              </label>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
