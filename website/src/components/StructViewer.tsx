import type { TypeInfo, TypeMember } from "../types/typeinfo";
import styles from "./StructViewer.module.css";

function StructMember({ member }: { member: TypeMember }) {
  const signIndicator = member.kind === "scalar" && !member.unsigned ? "±" : "";
  const fieldName = member.kind === "array"
    ? `${member.name}[${member.element_count}]`
    : member.name;

  return (
    <div className={styles.member}>
      <span className={styles.signIndicator}>{signIndicator}</span>
      <span className={styles.memberType}>{member.type}</span>
      <span className={styles.memberName}>{fieldName}</span>
      <span className={styles.memberOffset}>{member.offset}</span>
      <span className={styles.memberSize}>{member.size}</span>
    </div>
  );
}

function Struct({ struct }: { struct: TypeInfo }) {
  return (
    <div className={styles.struct}>
      <div className={styles.structHeader}>
        <strong>
          {struct.kind} {struct.name}
        </strong>
        <span className={styles.structMeta}>
          size: {struct.size}, align: {struct.align}
        </span>
      </div>
      {struct.kind === "struct" && (
        <div className={styles.structMembers}>
          <div className={styles.memberHeader}>
            <span></span>
            <span></span>
            <span></span>
            <span>offset</span>
            <span>size</span>
          </div>
          <div className={styles.headerBorder}></div>
          {struct.members.map((member, i) => (
            <StructMember key={i} member={member} />
          ))}
        </div>
      )}
    </div>
  );
}

interface StructViewerProps {
  typeInfo: TypeInfo;
  onClose: () => void;
}

export default function StructViewer({ typeInfo, onClose }: StructViewerProps) {
  return (
    <div className={styles.structViewer}>
      <div className={styles.header}>
        <h3>Type Information</h3>
        <button className={styles.closeButton} onClick={onClose}>
          ×
        </button>
      </div>
      <div>
        <Struct struct={typeInfo} />
      </div>
    </div>
  );
}
