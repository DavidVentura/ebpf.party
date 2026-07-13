import { useState } from "react";
import type { VerifierDiagnostic } from "../types/sse-events";
import styles from "./EventViewer.module.css";

export default function VerifierDiagnosticView({
  data,
}: {
  data: VerifierDiagnostic;
}) {
  const [showRaw, setShowRaw] = useState(false);

  return (
    <div className={styles.diagnostic}>
      <div className={styles.diagnosticTabs}>
        <button
          className={!showRaw ? styles.tabActive : styles.tab}
          onClick={() => setShowRaw(false)}
        >
          Diagnostic
        </button>
        <button
          className={showRaw ? styles.tabActive : styles.tab}
          onClick={() => setShowRaw(true)}
        >
          Raw verifier log
        </button>
      </div>
      <pre className={styles.diagnosticBody}>
        {showRaw ? data.raw : data.rendered}
      </pre>
    </div>
  );
}
