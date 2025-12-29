import styles from "./App.module.css";

interface CodeEditorProps {
  code: string;
  onChange: (code: string) => void;
}

export default function CodeEditor({ code, onChange }: CodeEditorProps) {
  return (
    <textarea
      className={styles.textarea}
      value={code}
      onChange={(e) => onChange(e.target.value)}
      placeholder="Write your C code here..."
      autoComplete="off"
    />
  );
}
