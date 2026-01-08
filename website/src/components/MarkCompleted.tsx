import { useEffect } from "react";

interface MarkCompletedProps {
  exerciseId: string;
}

export default function MarkCompleted({ exerciseId }: MarkCompletedProps) {
  useEffect(() => {
    localStorage.setItem(`exercise-completed-${exerciseId}`, "true");
  }, [exerciseId]);

  return null;
}
