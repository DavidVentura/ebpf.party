import CodeMirror from "@uiw/react-codemirror";
import { cpp } from "@codemirror/lang-cpp";
import { oneDark } from "@codemirror/theme-one-dark";
import { EditorView, keymap } from "@codemirror/view";
import { Prec } from "@codemirror/state";
import { syntaxTree } from "@codemirror/language";

interface CodeEditorProps {
  code: string;
  onChange: (code: string) => void;
  onRun: () => void;
  canRun: boolean;
  onSelectStruct: (name: string) => void;
}

export default function CodeEditor({
  code,
  onChange,
  onRun,
  canRun,
  onSelectStruct,
}: CodeEditorProps) {
  const ctrlClickHandler = EditorView.domEventHandlers({
    mousedown: (event, view) => {
      if (event.ctrlKey || event.metaKey) {
        const pos = view.posAtCoords({ x: event.clientX, y: event.clientY });
        if (pos !== null) {
          const tree = syntaxTree(view.state);
          const node = tree.resolveInner(pos, 1);

          if (node && node.type.name === "TypeIdentifier") {
            const text = view.state.doc.sliceString(node.from, node.to);
            onSelectStruct(text);
            event.preventDefault();
            return true;
          }
        }
      }
      return false;
    },
  });

  const ctrlEnterHandler = Prec.highest(
    keymap.of([
      {
        key: "Mod-Enter",
        run: () => {
          if (canRun) onRun();
          return true;
        },
      },
    ])
  );
  const extensions = [cpp(), ctrlEnterHandler, ctrlClickHandler];

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
