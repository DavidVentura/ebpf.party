import type { SSEEvent } from "../types/sse-events";
import type { TypeInfo } from "../types/typeinfo";
import ParsedEventViewer from "./ParsedEventViewer";
import styles from "./EventViewer.module.css";

interface EventViewerProps {
  events: SSEEvent[];
  isRunning: boolean;
  onClear: () => void;
  typeRegistry: { [name: string]: TypeInfo };
}

export default function EventViewer({
  events,
  isRunning,
  onClear,
  typeRegistry,
}: EventViewerProps) {
  const isError = (event: SSEEvent): boolean => {
    if (event.type === "compileError") return true;
    if (event.type === "guestMessage") {
      if (event.data.type === "debugMapNotFound") return true;
      if (event.data.type === "noProgramsFound") return true;
      if (event.data.type === "verifierFail") return true;
    }
    return false;
  };

  const formatEvent = (event: SSEEvent): string => {
    if (event.type === "compileError") {
      return event.data;
    }
    if (event.type === "guestMessage") {
      if (event.data.type === "debugMapNotFound") {
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
        {events
          .filter(
            (event) => ["compiling", "booting", "stack"].indexOf(event.type) < 0
          )
          .filter(
            (event) =>
              event.type !== "guestMessage" ||
              ["booted", "foundProgram", "finished"].indexOf(event.data.type) ==
                -1
          )
          .map((event, i) => {
            if (event.type === "guestMessage" && event.data.type === "event") {
              return (
                <ParsedEventViewer
                  key={i}
                  data={event.data.data}
                  typeRegistry={typeRegistry}
                />
              );
            }

            return (
              <p
                key={i}
                className={isError(event) ? styles.errorEvent : styles.event}
              >
                {formatEvent(event)}
              </p>
            );
          })}
      </div>
    </div>
  );
}
