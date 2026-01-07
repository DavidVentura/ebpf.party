import Loader from "lucide-react/dist/esm/icons/loader";
import Play from "lucide-react/dist/esm/icons/play";
import ChevronDown from "lucide-react/dist/esm/icons/chevron-down";
import styles from "./RunButton.module.css";

interface RunButtonProps {
  disabled: boolean;
  isRunning: boolean;
  onRun: () => void;
  onDropdownClick: () => void;
  dropdownButtonRef?: React.RefObject<HTMLButtonElement>;
}

export default function RunButton({
  disabled,
  isRunning,
  onRun,
  onDropdownClick,
  dropdownButtonRef,
}: RunButtonProps) {
  return (
    <div className={styles.buttonGroup}>
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
      <button
        ref={dropdownButtonRef}
        className={styles.dropdownButton}
        onClick={onDropdownClick}
        title="Settings"
      >
        <ChevronDown size={16} />
      </button>
    </div>
  );
}
