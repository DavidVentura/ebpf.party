import CodeMirror from "@uiw/react-codemirror";
import { cpp } from "@codemirror/lang-cpp";
import { oneDark } from "@codemirror/theme-one-dark";
import { keymap } from "@codemirror/view";
import { Prec } from "@codemirror/state";

interface CodeEditorProps {
  code: string;
  onChange: (code: string) => void;
  onRun: () => void;
  canRun: boolean;
}

export default function CodeEditor({
  code,
  onChange,
  onRun,
  canRun,
}: CodeEditorProps) {
  const extensions = [
    cpp(),
    Prec.highest(
      keymap.of([
        {
          key: "Ctrl-Enter",
          run: () => {
            console.log("ctrl-enter");
            if (canRun) onRun();
            return true;
          },
        },
      ])
    ),
  ];

  return (
    <CodeMirror
      value={code}
      height="100%"
      theme={oneDark}
      extensions={extensions}
      onChange={onChange}
      placeholder="Write your C code here..."
      basicSetup={{
        lineNumbers: true,
        highlightActiveLineGutter: true,
        highlightSpecialChars: false,
        foldGutter: false,
        drawSelection: false,
        dropCursor: false,
        allowMultipleSelections: false,
        indentOnInput: true,
        bracketMatching: true,
        closeBrackets: false,
        autocompletion: false,
        rectangularSelection: false,
        crosshairCursor: false,
        highlightActiveLine: true,
        highlightSelectionMatches: true,
        closeBracketsKeymap: false,
        searchKeymap: false,
        foldKeymap: false,
        completionKeymap: false,
        lintKeymap: false,
      }}
    />
  );
}
