import type { TypeInfo, TypeMember } from "../types/typeinfo";
import styles from "./StructViewer.module.css";

function StructMember({ member }: { member: TypeMember }) {
  let meta = `offset: ${member.offset}, size: ${member.size}`;

  if (member.kind === "scalar" && member.unsigned) {
    meta += ", unsigned";
  } else if (member.kind === "array") {
    meta += `, [${member.element_count}]`;
  }

  return (
    <div className={styles.member}>
      <span className={styles.memberType}>{member.type}</span>
      <span className={styles.memberName}>{member.name}</span>
      <span className={styles.memberMeta}>{meta}</span>
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
