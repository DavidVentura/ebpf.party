import { useEffect, useState } from 'react';
import type { ContentMetadata } from '../lib/exercises-metadata';

interface ExerciseListProps {
  metadata: ContentMetadata;
}

export default function ExerciseList({ metadata }: ExerciseListProps) {
  const [completedExercises, setCompletedExercises] = useState<Set<string>>(new Set());

  useEffect(() => {
    const completed = new Set<string>();
    metadata.chapters.forEach(chapter => {
      chapter.exercises.forEach(exercise => {
        if (localStorage.getItem(`exercise-completed-${exercise.exerciseId}`) === 'true') {
          completed.add(exercise.exerciseId);
        }
      });
    });
    setCompletedExercises(completed);
  }, []);

  return (
    <>
      {metadata.chapters.map((chapter) => (
        <section key={chapter.slug} className="chapter">
          <h2>
            <span className="chapter-number">Chapter {chapter.number}:</span>{" "}
            {chapter.title}
          </h2>
          <ul>
            {chapter.exercises.map((exercise) => {
              const url = `/exercises/${chapter.slug}/${exercise.slug}`;
              const isCompleted = completedExercises.has(exercise.exerciseId);

              return (
                <li key={exercise.slug}>
                  {exercise.incomplete && !import.meta.env.DEV ? (
                    <span>{exercise.title} (coming soon)</span>
                  ) : (
                    <>
                      <a href={url}>{exercise.title}</a>
                      {isCompleted && <span className="completion-indicator">✓</span>}
                    </>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </>
  );
}
