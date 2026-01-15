import { useMemo, useSyncExternalStore } from "react";
import CodeMirror from "@uiw/react-codemirror";
import { cpp } from "@codemirror/lang-cpp";
import { EditorView, keymap } from "@codemirror/view";
import { Prec } from "@codemirror/state";
import {
  HighlightStyle,
  indentUnit,
  syntaxHighlighting,
  syntaxTree,
} from "@codemirror/language";
import { oneDark } from "@codemirror/theme-one-dark";
import { tags as t } from "@lezer/highlight";
import { vim } from "@replit/codemirror-vim";

const rosePineDawnTheme = EditorView.theme(
  {
    "&": {
      color: "#575279",
    },
    ".cm-content": {
      caretColor: "#575279",
    },
    ".cm-cursor, .cm-dropCursor": {
      borderLeftColor: "#575279",
    },
    "&.cm-focused > .cm-scroller > .cm-selectionLayer .cm-selectionBackground, .cm-selectionBackground, .cm-content ::selection":
      {
        backgroundColor: "#6e6a8614",
      },
    ".cm-gutters": {
      color: "#57527970",
      border: "none",
    },
    ".cm-activeLine": {
      backgroundColor: "#6e6a860d",
    },
    ".cm-activeLineGutter": {
      backgroundColor: "#6e6a860d",
    },
  },
  { dark: false }
);

const rosePineDawnHighlight = HighlightStyle.define([
  { tag: t.comment, color: "#9893a5" },
  { tag: [t.bool, t.null], color: "#286983" },
  { tag: t.number, color: "#d7827e" },
  { tag: t.className, color: "#d7827e" },
  { tag: [t.angleBracket, t.tagName, t.typeName], color: "#56949f" },
  { tag: t.attributeName, color: "#907aa9" },
  { tag: t.punctuation, color: "#797593" },
  { tag: [t.keyword, t.modifier], color: "#286983" },
  { tag: [t.string, t.regexp], color: "#ea9d34" },
  { tag: t.variableName, color: "#d7827e" },
]);

const rosePineDawn = [
  rosePineDawnTheme,
  syntaxHighlighting(rosePineDawnHighlight),
];

const darkModeQuery =
  typeof window !== "undefined"
    ? window.matchMedia("(prefers-color-scheme: dark)")
    : null;

function subscribeToColorScheme(callback: () => void) {
  darkModeQuery?.addEventListener("change", callback);
  return () => darkModeQuery?.removeEventListener("change", callback);
}

function getColorScheme() {
  return darkModeQuery?.matches ?? true;
}

interface CodeEditorProps {
  code: string;
  onChange: (code: string) => void;
  onRun: () => void;
  canRun: boolean;
  onSelectStruct: (name: string) => void;
  vimMode: boolean;
}

export default function CodeEditor({
  code,
  onChange,
  onRun,
  canRun,
  onSelectStruct,
  vimMode,
}: CodeEditorProps) {
  const isDark = useSyncExternalStore(
    subscribeToColorScheme,
    getColorScheme,
    () => true
  );

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

  const extensions = useMemo(
    () => [
      ...(vimMode ? [vim()] : []),
      cpp(),
      ctrlEnterHandler,
      ctrlClickHandler,
      indentUnit.of("    "),
      EditorView.lineWrapping,
      // ...(isDark ? [oneDark] : rosePineDawn),
      oneDark,
    ],
    [vimMode, isDark, ctrlEnterHandler, ctrlClickHandler]
  );

  return (
    <CodeMirror
      value={code}
      height="100%"
      // theme={oneDark}
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
