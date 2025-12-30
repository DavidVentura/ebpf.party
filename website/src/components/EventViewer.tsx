import type { SSEEvent } from "../types/sse-events";
import styles from "./EventViewer.module.css";

interface EventViewerProps {
  events: SSEEvent[];
  isRunning: boolean;
  onClear: () => void;
}

export default function EventViewer({ events, isRunning, onClear }: EventViewerProps) {
  const isError = (event: SSEEvent): boolean => {
    if (event.type === "compileError") return true;
    if (event.type === "executionResult") {
      if (event.data.type === "noPerfMapsFound") return true;
      if (event.data.type === "noProgramsFound") return true;
      if (event.data.type === "verifierFail") return true;
    }
    return false;
  };

  const formatEvent = (event: SSEEvent): string => {
    if (event.type === "compileError") {
      return event.data;
    }
    if (event.type === "executionResult") {
      if (event.data.type === "noPerfMapsFound") {
        return "Error: No perf maps found in program";
      }
      if (event.data.type === "noProgramsFound") {
        return "Error: No eBPF programs found in code. Missing a SEC() decorator?";
      }
      if (event.data.type === "verifierFail") {
        return event.data.data;
      }
      return `${event.data.type}: ${JSON.stringify(event.data.data)}`;
    }
    return event.type;
  };

  return (
    <div className={styles.eventViewer}>
      <div className={styles.header}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <h3>Execution Events</h3>
          {isRunning && <span className={styles.loading}>Loading...</span>}
        </div>
        <button className={styles.closeButton} onClick={onClear}>
          ×
        </button>
      </div>
      <div className={styles.events}>
        {events.map((event, i) => (
          <p
            key={i}
            className={isError(event) ? styles.errorEvent : styles.event}
          >
            {formatEvent(event)}
          </p>
        ))}
      </div>
    </div>
  );
}
