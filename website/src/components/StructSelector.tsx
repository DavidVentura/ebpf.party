import type { TypeInfo } from "../types/typeinfo";
import styles from "./StructSelector.module.css";

interface StructSelectorProps {
  structs: { [name: string]: TypeInfo };
  selectedName: string;
  onSelect: (name: string) => void;
}

export default function StructSelector({
  structs,
  selectedName,
  onSelect,
}: StructSelectorProps) {
  const structNames = Object.keys(structs);

  return (
    <div className={styles.structSelector}>
      <label htmlFor="struct-select">Select struct to view:</label>
      <select
        id="struct-select"
        value={selectedName}
        onChange={(e) => onSelect(e.target.value)}
      >
        {structNames.map((name) => (
          <option key={name} value={name}>
            {name}
          </option>
        ))}
      </select>
    </div>
  );
}
