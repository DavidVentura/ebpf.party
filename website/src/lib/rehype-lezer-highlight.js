import { visit } from 'unist-util-visit';
import { cpp } from '@codemirror/lang-cpp';
import { highlightTree, tags } from '@lezer/highlight';

const TAG_TO_CLASS = {
  [tags.keyword]: 'token-keyword',
  [tags.controlKeyword]: 'token-keyword',
  [tags.operatorKeyword]: 'token-keyword',
  [tags.definitionKeyword]: 'token-keyword',
  [tags.moduleKeyword]: 'token-keyword',
  [tags.function]: 'token-function',
  [tags.variableName]: 'token-function',
  [tags.string]: 'token-string',
  [tags.character]: 'token-string',
  [tags.comment]: 'token-comment',
  [tags.lineComment]: 'token-comment',
  [tags.blockComment]: 'token-comment',
  [tags.number]: 'token-constant',
  [tags.integer]: 'token-constant',
  [tags.float]: 'token-constant',
  [tags.bool]: 'token-constant',
  [tags.typeName]: 'token-constant',
  [tags.className]: 'token-constant',
  [tags.macroName]: 'token-keyword',
  [tags.operator]: 'token-punctuation',
  [tags.punctuation]: 'token-punctuation',
  [tags.separator]: 'token-punctuation',
  [tags.brace]: 'token-punctuation',
  [tags.paren]: 'token-punctuation',
  [tags.bracket]: 'token-punctuation',
};

const highlighter = {
  style(tagSet) {
    for (const tag of tagSet) {
      if (TAG_TO_CLASS[tag]) {
        return TAG_TO_CLASS[tag];
      }
    }

    const hasUnknownTag = tagSet.some(t => t.id === 92);
    if (hasUnknownTag) {
      return 'token-function';
    }

    return '';
  }
};

export default function rehypeLezerHighlight() {
  const cppLang = cpp();
  const language = cppLang.language;

  return (tree) => {
    visit(tree, 'element', (node) => {
      if (node.tagName !== 'pre') return;

      const codeNode = node.children.find(
        (child) => child.type === 'element' && child.tagName === 'code'
      );

      if (!codeNode) return;

      const className = codeNode.properties?.className || [];
      const isC = className.some(
        (cls) => cls === 'language-c' || cls === 'language-cpp'
      );

      if (!isC) return;

      const codeText = codeNode.children
        .filter((child) => child.type === 'text')
        .map((child) => child.value)
        .join('');

      const parseTree = language.parser.parse(codeText);

      const highlightedChildren = [];
      let lastPos = 0;

      highlightTree(parseTree, highlighter, (from, to, classes) => {
        const text = codeText.slice(from, to);

        if (from > lastPos) {
          const gapText = codeText.slice(lastPos, from);
          if (gapText) {
            const punctuationRegex = /[;,]/g;
            let gapLastPos = 0;
            let match;

            while ((match = punctuationRegex.exec(gapText)) !== null) {
              if (match.index > gapLastPos) {
                highlightedChildren.push({
                  type: 'text',
                  value: gapText.slice(gapLastPos, match.index)
                });
              }

              highlightedChildren.push({
                type: 'element',
                tagName: 'span',
                properties: { className: ['token-punctuation'] },
                children: [{ type: 'text', value: match[0] }]
              });

              gapLastPos = match.index + 1;
            }

            if (gapLastPos < gapText.length) {
              highlightedChildren.push({
                type: 'text',
                value: gapText.slice(gapLastPos)
              });
            }
          }
        }

        if (classes) {
          highlightedChildren.push({
            type: 'element',
            tagName: 'span',
            properties: { className: [classes] },
            children: [{ type: 'text', value: text }],
          });
        } else {
          if (text) {
            highlightedChildren.push({ type: 'text', value: text });
          }
        }

        lastPos = to;
      });

      if (lastPos < codeText.length) {
        const text = codeText.slice(lastPos);
        if (text) {
          highlightedChildren.push({ type: 'text', value: text });
        }
      }

      codeNode.children = highlightedChildren;
    });
  };
}
