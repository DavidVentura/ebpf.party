import type { SSEEvent } from "../types/sse-events";
import type { TypeInfo } from "../types/typeinfo";
import ParsedEventViewer from "./ParsedEventViewer";
import VerifierDiagnosticView from "./VerifierDiagnosticView";
import styles from "./EventViewer.module.css";
import X from "lucide-react/dist/esm/icons/x";

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
  const getEventStyle = (
    event: SSEEvent
  ): "error" | "success" | "warning" | "normal" => {
    if (event.type === "compileError") return "error";
    if (event.type === "requestError") return "error";
    if (event.type === "wrongAnswer") return "error";
    if (event.type === "correctAnswer") return "success";
    if (event.type === "multipleAnswers") return "warning";
    if (event.type === "noAnswer") return "warning";
    if (event.type === "guestMessage") {
      if (event.data.type === "debugMapNotFound") return "error";
      if (event.data.type === "noProgramsFound") return "error";
      if (event.data.type === "cantAttachProgram") return "error";
      if (event.data.type === "verifierFail") return "error";
      if (event.data.type === "crashed") return "error";
    }
    return "normal";
  };

  const formatEvent = (event: SSEEvent): string => {
    if (event.type === "compileError") {
      return event.data;
    }
    if (event.type === "requestError") {
      return `Request Error: ${event.data}`;
    }
    if (event.type === "correctAnswer") {
      return "Correct Answer!";
    }
    if (event.type === "wrongAnswer") {
      return "Wrong Answer";
    }
    if (event.type === "multipleAnswers") {
      return "Multiple Answers Detected";
    }
    if (event.type === "noAnswer") {
      return "You didn't submit an answer. Use SUBMIT_STR or SUBMIT_NUM to do it.";
    }
    if (event.type === "guestMessage") {
      if (event.data.type === "debugMapNotFound") {
        return "Error: No perf maps found in program";
      }
      if (event.data.type === "noProgramsFound") {
        return "Error: No eBPF programs found in code. Missing a SEC() decorator?";
      }
      if (event.data.type === "cantAttachProgram") {
        const { section, kind } = event.data.data;
        if (kind === "noSuchHook") {
          return `Could not attach to \`${section}\`, check the hook name for a typo.`;
        }
        if (kind === "denied") {
          return `The kernel rejected the program for hook \`${section}\`. Usually this is an over-read of ctx.`;
        }
        return `Could not attach to \`${section}\`.`;
      }
      if (event.data.type === "verifierFail") {
        return event.data.data;
      }
      return `${event.data.type}: ${JSON.stringify(event.data.data)}`;
    }
    return event.type;
  };

  // When a structured diagnostic is present, the raw verifierFail row is
  // redundant: the diagnostic component shows the raw log under its own tab.
  const hasDiagnostic = events.some((e) => e.type === "verifierDiagnostic");

  // If anything errored, the program never ran, so a "you didn't submit an
  // answer" warning is noise — there was no chance to submit one.
  const hasError = events.some((e) => getEventStyle(e) === "error");

  return (
    <div className={styles.eventViewer}>
      <div className={styles.header}>
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <h3>Execution Events</h3>
          {isRunning && <span className={styles.loading}>Loading...</span>}
        </div>
        <button className={styles.closeButton} onClick={onClear}>
          <X></X>
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
          .filter(
            (event) =>
              !hasDiagnostic ||
              event.type !== "guestMessage" ||
              event.data.type !== "verifierFail"
          )
          .filter((event) => !(hasError && event.type === "noAnswer"))
          .map((event, i) => {
            if (event.type === "verifierDiagnostic") {
              return <VerifierDiagnosticView key={i} data={event.data} />;
            }
            if (event.type === "guestMessage" && event.data.type === "event") {
              return (
                <ParsedEventViewer
                  key={i}
                  data={event.data.data}
                  typeRegistry={typeRegistry}
                />
              );
            }

            const eventStyle = getEventStyle(event);
            const className =
              eventStyle === "error"
                ? styles.errorEvent
                : eventStyle === "success"
                ? styles.successEvent
                : eventStyle === "warning"
                ? styles.warningEvent
                : styles.event;

            return (
              <p key={i} className={className}>
                {formatEvent(event)}
              </p>
            );
          })}
      </div>
    </div>
  );
}
