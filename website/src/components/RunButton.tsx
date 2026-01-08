import Loader from "lucide-react/dist/esm/icons/loader";
import Play from "lucide-react/dist/esm/icons/play";
import styles from "./RunButton.module.css";

interface RunButtonProps {
  disabled: boolean;
  isRunning: boolean;
  onRun: () => void;
}

export default function RunButton({
  disabled,
  isRunning,
  onRun,
}: RunButtonProps) {
  return (
    <button
      className={styles.runButton}
      onClick={onRun}
      disabled={disabled || isRunning}
    >
      {isRunning ? (
        <Loader size={16} />
      ) : (
        <>
          <Play size={16} />
          Run
        </>
      )}
    </button>
  );
}
