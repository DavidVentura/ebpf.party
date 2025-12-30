import { useState } from "react";
import type { TypeInfo } from "../types/typeinfo";
import { parseStruct, type ParsedField, type ParsedValue } from "../lib/struct-parser";
import { debTypeRegistry } from "../lib/deb-type-registry";
import styles from "./ParsedEventViewer.module.css";

interface ParsedEventViewerProps {
  data: number[];
  typeRegistry: { [name: string]: TypeInfo };
}

interface ParsedFieldProps {
  field: ParsedField;
  path: string;
  charArrayModes: { [path: string]: "string" | "hex" };
  onToggle: (path: string) => void;
  depth: number;
}

function ParsedFieldComponent({
  field,
  path,
  charArrayModes,
  onToggle,
  depth,
}: ParsedFieldProps) {
  const indentStyle = { paddingLeft: `${depth * 1.5}rem` };

  if (field.value.kind === "scalar") {
    return (
      <div className={styles.field}>
        <span className={styles.fieldName} style={indentStyle}>{field.name}</span>
        <span className={styles.togglePlaceholder}></span>
        <span className={styles.fieldValue}>{field.value.value.toString()}</span>
      </div>
    );
  }

  if (field.value.kind === "string") {
    const mode = charArrayModes[path] || "string";
    const displayValue =
      mode === "string"
        ? `"${field.value.value}"`
        : field.value.rawBytes.map((b) => b.toString(16).padStart(2, "0")).join(" ");

    return (
      <div className={styles.field}>
        <span className={styles.fieldName} style={indentStyle}>{field.name}</span>
        <button className={styles.toggleButton} onClick={() => onToggle(path)}>
          [
          <span className={mode === "string" ? styles.activeMode : ""}>
            a-z
          </span>
          |
          <span className={mode === "hex" ? styles.activeMode : ""}>0x</span>]
        </button>
        <span className={styles.fieldValue}>{displayValue}</span>
      </div>
    );
  }

  if (field.value.kind === "struct") {
    return (
      <>
        <div className={styles.field}>
          <span className={styles.fieldName} style={indentStyle}>{field.name}</span>
          <span className={styles.togglePlaceholder}></span>
          <span className={styles.fieldValue}></span>
        </div>
        {field.value.fields.map((subField, i) => (
          <ParsedFieldComponent
            key={i}
            field={subField}
            path={`${path}.${subField.name}`}
            charArrayModes={charArrayModes}
            onToggle={onToggle}
            depth={depth + 1}
          />
        ))}
      </>
    );
  }

  if (field.value.kind === "array") {
    const nestedIndentStyle = { paddingLeft: `${(depth + 1) * 1.5}rem` };
    return (
      <>
        <div className={styles.field}>
          <span className={styles.fieldName} style={indentStyle}>{field.name}</span>
          <span className={styles.togglePlaceholder}></span>
          <span className={styles.fieldValue}></span>
        </div>
        {field.value.elements.map((element, i) => (
          <div key={i} className={styles.field}>
            <span className={styles.fieldName} style={nestedIndentStyle}>[{i}]</span>
            <span className={styles.togglePlaceholder}></span>
            <span className={styles.fieldValue}>
              {element.kind === "scalar" ? element.value.toString() : JSON.stringify(element)}
            </span>
          </div>
        ))}
      </>
    );
  }

  return null;
}

export default function ParsedEventViewer({
  data,
  typeRegistry,
}: ParsedEventViewerProps) {
  const [charArrayModes, setCharArrayModes] = useState<{
    [path: string]: "string" | "hex";
  }>({});

  const toggleCharArrayMode = (path: string) => {
    setCharArrayModes((prev) => ({
      ...prev,
      [path]: prev[path] === "hex" ? "string" : "hex",
    }));
  };

  if (data.length < 2) {
    return (
      <div className={styles.parsedEvent}>
        <div className={styles.eventHeader}>
          <span className={styles.eventError}>Parse Error</span>
        </div>
        <div className={styles.errorMessage}>
          Data too short: expected at least 2 bytes for type prefix, got {data.length}
        </div>
      </div>
    );
  }

  const typeId = data[0];
  const counter = data[1];

  const debTypeInfo = debTypeRegistry.findByCounter(counter);

  if (!debTypeInfo) {
    return (
      <div className={styles.parsedEvent}>
        <div className={styles.eventHeader}>
          <span className={styles.eventError}>Parse Error</span>
        </div>
        <div className={styles.errorMessage}>
          Unknown counter: {counter} (not found in debug type registry)
        </div>
      </div>
    );
  }

  const typeName = debTypeInfo.type_name;
  const label = debTypeInfo.label;

  // Handle scalar type (type_id 2) - has 3-byte header with size
  if (typeId === 2) {
    if (data.length < 3) {
      return (
        <div className={styles.parsedEvent}>
          <div className={styles.eventHeader}>
            <span className={styles.eventError}>Parse Error</span>
          </div>
          <div className={styles.errorMessage}>
            Scalar type requires 3-byte header, got {data.length} bytes
          </div>
        </div>
      );
    }

    const size = data[2];
    const actualData = data.slice(3);
    let value: number | bigint;
    const view = new DataView(new Uint8Array(actualData).buffer);
    const isSigned = debTypeInfo.is_signed || false;

    // Read based on size byte
    if (size === 1) {
      value = isSigned ? view.getInt8(0) : view.getUint8(0);
    } else if (size === 2) {
      value = isSigned ? view.getInt16(0, true) : view.getUint16(0, true);
    } else if (size === 4) {
      value = isSigned ? view.getInt32(0, true) : view.getUint32(0, true);
    } else if (size === 8) {
      value = isSigned ? view.getBigInt64(0, true) : view.getBigUint64(0, true);
    } else {
      value = 0;
    }

    return (
      <div className={styles.parsedEvent}>
        <div className={styles.eventHeader}>
          <span className={styles.eventType}>{label}</span>
          <span className={styles.eventSize}>({size} bytes)</span>
        </div>
        <div className={styles.fields}>
          <div className={styles.field}>
            <span className={styles.fieldName}>value</span>
            <span className={styles.togglePlaceholder}></span>
            <span className={styles.fieldValue}>{value.toString()}</span>
          </div>
        </div>
      </div>
    );
  }

  // Handle string type (type_id 3) - 2-byte header
  const actualData = data.slice(2);

  if (typeId === 3) {
    const mode = charArrayModes["_string"] || "string";
    const decoder = new TextDecoder("utf-8", { fatal: false });
    const stringValue = decoder.decode(new Uint8Array(actualData));
    const displayValue =
      mode === "string"
        ? `"${stringValue}"`
        : actualData.map((b) => b.toString(16).padStart(2, "0")).join(" ");

    return (
      <div className={styles.parsedEvent}>
        <div className={styles.eventHeader}>
          <span className={styles.eventType}>{label}</span>
          <span className={styles.eventSize}>({actualData.length} bytes)</span>
        </div>
        <div className={styles.fields}>
          <div className={styles.field}>
            <span className={styles.fieldName}>value</span>
            <button className={styles.toggleButton} onClick={() => toggleCharArrayMode("_string")}>
              [
              <span className={mode === "string" ? styles.activeMode : ""}>
                a-z
              </span>
              |
              <span className={mode === "hex" ? styles.activeMode : ""}>0x</span>]
            </button>
            <span className={styles.fieldValue}>{displayValue}</span>
          </div>
        </div>
      </div>
    );
  }

  // Handle struct type (type_id 4)
  const typeInfo = typeRegistry[typeName];

  if (!typeInfo) {
    return (
      <div className={styles.parsedEvent}>
        <div className={styles.eventHeader}>
          <span className={styles.eventError}>Parse Error</span>
        </div>
        <div className={styles.errorMessage}>
          Type '{typeName}' not found in type registry
        </div>
      </div>
    );
  }

  const parseResult = parseStruct(actualData, typeInfo, typeRegistry);

  if (!parseResult.success) {
    return (
      <div className={styles.parsedEvent}>
        <div className={styles.eventHeader}>
          <span className={styles.eventType}>{label}</span>
          <span className={styles.eventError}>Parse Error</span>
        </div>
        <div className={styles.errorMessage}>{parseResult.error}</div>
      </div>
    );
  }

  return (
    <div className={styles.parsedEvent}>
      <div className={styles.eventHeader}>
        <span className={styles.eventType}>{label}</span>
        <span className={styles.eventSize}>({actualData.length} bytes)</span>
      </div>
      <div className={styles.fields}>
        {parseResult.parsed!.map((field, i) => (
          <ParsedFieldComponent
            key={i}
            field={field}
            path={field.name}
            charArrayModes={charArrayModes}
            onToggle={toggleCharArrayMode}
            depth={0}
          />
        ))}
      </div>
    </div>
  );
}
