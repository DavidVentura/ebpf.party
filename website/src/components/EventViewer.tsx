import type { SSEEvent } from "../types/sse-events";
import styles from "./EventViewer.module.css";

interface EventViewerProps {
  events: SSEEvent[];
  isRunning: boolean;
}

export default function EventViewer({ events, isRunning }: EventViewerProps) {
  return (
    <div className={styles.eventViewer}>
      <h3>Execution Events</h3>
      <div className={styles.events}>
        {events.map((event, i) => (
          <p key={i} className={styles.event}>
            {event.type === "executionResult"
              ? `${event.data.type}: ${JSON.stringify(event.data.data)}`
              : event.type}
          </p>
        ))}
        {isRunning && <p className={styles.loading}>Loading...</p>}
      </div>
    </div>
  );
}
