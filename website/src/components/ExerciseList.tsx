import { useEffect, useState } from "react";
import type { ContentMetadata } from "../lib/exercises-metadata";
import styles from "./ExerciseList.module.css";

interface ExerciseListProps {
  metadata: ContentMetadata;
}

export default function ExerciseList({ metadata }: ExerciseListProps) {
  const [completedExercises, setCompletedExercises] = useState<Set<string>>(
    new Set()
  );

  useEffect(() => {
    const completed = new Set<string>();
    metadata.chapters.forEach((chapter) => {
      chapter.exercises.forEach((exercise) => {
        if (
          localStorage.getItem(`exercise-completed-${exercise.exerciseId}`) ===
          "true"
        ) {
          completed.add(exercise.exerciseId);
        }
      });
    });
    setCompletedExercises(completed);
  }, []);

  return (
    <>
      {metadata.chapters.map((chapter) => (
        <section key={chapter.slug} className={styles.chapter}>
          <h2 className={styles.chapterHeader}>
            <span className={styles.chapterNumber}>
              Chapter {chapter.number}:
            </span>{" "}
            {chapter.title}
          </h2>
          <div className={styles.chapterBox}>
            {chapter.exercises
              .filter(
                (exercise) => !!exercise.incomplete || import.meta.env.DEV
              )
              .map((exercise, index) => {
                const url = `/exercises/${chapter.slug}/${exercise.slug}`;
                const isCompleted = completedExercises.has(exercise.exerciseId);
                const hexNum = `0x${index.toString(16).padStart(2, "0")}`;

                return (
                  <a
                    key={exercise.slug}
                    href={url}
                    className={styles.exerciseRow}
                  >
                    <span className={styles.exerciseHex}>{hexNum}</span>
                    <span className={styles.exerciseCompletion}>
                      {isCompleted ? "✓" : ""}
                    </span>
                    <span className={styles.exerciseTitle}>
                      {exercise.title}
                    </span>
                  </a>
                );
              })}
          </div>
        </section>
      ))}
    </>
  );
}
