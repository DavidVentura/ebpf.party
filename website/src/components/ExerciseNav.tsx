import { ChevronLeft, ChevronRight } from "lucide-react";
import styles from "./ExerciseNav.module.css";

interface Exercise {
  url?: string;
  frontmatter: {
    title: string;
  };
}

interface ExerciseNavProps {
  prevExercise?: Exercise | null;
  nextExercise?: Exercise | null;
}

export default function ExerciseNav({
  prevExercise,
  nextExercise,
}: ExerciseNavProps) {
  return (
    <nav className={styles.exerciseNav}>
      {prevExercise && (
        <a
          href={prevExercise.url}
          className={`${styles.navLink} ${styles.prev}`}
        >
          <span className={styles.navArrow}>
            <ChevronLeft />
          </span>
          <div className={styles.navText}>
            <div className={styles.navLabel}>Previous</div>
            <div className={styles.navTitle}>
              {prevExercise.frontmatter.title}
            </div>
          </div>
        </a>
      )}
      {nextExercise && (
        <a
          href={nextExercise.url}
          className={`${styles.navLink} ${styles.next}`}
        >
          <div className={styles.navText}>
            <div className={styles.navLabel}>Next</div>
            <div className={styles.navTitle}>
              {nextExercise.frontmatter.title}
            </div>
          </div>
          <span className={styles.navArrow}>
            <ChevronRight />
          </span>
        </a>
      )}
    </nav>
  );
}
