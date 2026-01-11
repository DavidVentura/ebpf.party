import type { FuncDoc as FuncDocType } from "../types/function-docs";
import styles from "./FuncDoc.module.css";

interface FuncDocProps {
  doc: FuncDocType;
}

export default function FuncDoc({ doc }: FuncDocProps) {
  return (
    <details>
      <summary>{doc.description}</summary>
      <div className={styles.function}>
        Function
        <span className={styles.signature}> {doc.function_name} </span>
        <a
          className={styles.docsLink}
          href={doc.docsUrl}
          target="_blank"
          rel="noopener noreferrer"
        >
          Full documentation
        </a>
        <dl className={styles.args}>
          {doc.args && doc.args.length > 0 && (
            <>
              <dt>Args:</dt>
              {doc.args.map((arg, index) => (
                <dd key={index}>
                  <code>
                    {arg.type} {arg.name}
                  </code>
                  {arg.description}
                </dd>
              ))}
            </>
          )}
        </dl>
        {doc.returns && (
          <>
            {doc.returns.description.success ? (
              <>
                <div>On success, returns {doc.returns.description.success}</div>
                <div>On error, returns {doc.returns.description.error}</div>
              </>
            ) : (
              <>Returns {doc.returns.description}</>
            )}
          </>
        )}
      </div>
    </details>
  );
}
