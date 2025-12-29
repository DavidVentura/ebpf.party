import styles from "./RunButton.module.css";

interface RunButtonProps {
  disabled: boolean;
  isRunning: boolean;
  onRun: () => void;
}

export default function RunButton({ disabled, isRunning, onRun }: RunButtonProps) {
  return (
    <button
      className={styles.runButton}
      onClick={onRun}
      disabled={disabled || isRunning}
    >
      {isRunning ? "Running..." : "Run"}
    </button>
  );
}
