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
  [tags.propertyName]: 'token-keyword',
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
  [tags.squareBracket]: 'token-punctuation',
  [tags.angleBracket]: 'token-punctuation',
};

const highlighter = {
  style(tagSet) {
    // Log what tags we're seeing
    const tagNames = [];
    const tagIds = [];
    for (const tag of tagSet) {
      tagIds.push(tag.id);
      let found = false;
      for (const [name, value] of Object.entries(tags)) {
        if (value === tag) {
          tagNames.push(`${name}(${tag.id})`);
          found = true;
          break;
        }
      }
      if (!found) {
        tagNames.push(`UNNAMED(${tag.id})`);
      }
    }
    if (tagNames.length > 0) {
      console.log(`  Highlighter.style called with tags: ${tagNames.join(', ')}`);
    } else {
      console.log(`  Highlighter.style called with empty tagSet`);
    }

    for (const tag of tagSet) {
      if (TAG_TO_CLASS[tag]) {
        console.log(`    -> Returning class: ${TAG_TO_CLASS[tag]}`);
        return TAG_TO_CLASS[tag];
      }
    }

    // Check for specific unknown tag IDs we've identified
    const hasTag85 = tagSet.some(t => t.id === 85);
    const hasTag87 = tagSet.some(t => t.id === 87);
    const hasTag91 = tagSet.some(t => t.id === 91);
    const hasTag92 = tagSet.some(t => t.id === 92);

    if (hasTag85) {
      console.log(`    -> Tag 85 detected (macro/function), returning token-function`);
      return 'token-function';
    }

    if (hasTag87) {
      console.log(`    -> Tag 87 detected (builtin type), returning token-keyword`);
      return 'token-keyword';
    }

    if (hasTag91) {
      console.log(`    -> Tag 91 detected (function call at pos 0), returning token-function`);
      return 'token-function';
    }

    if (hasTag92) {
      console.log(`    -> Tag 92 detected (function call), returning token-function`);
      return 'token-function';
    }

    // CRITICAL: Never return empty string or null, always return a class
    // Otherwise highlightTree skips the callback entirely
    console.log(`    -> No match, returning fallback class 'token-unknown'`);
    return 'token-unknown';
  }
};

export default function rehypeLezerHighlight() {
  const cppLang = cpp();
  const language = cppLang.language;

  // Debug: log all tag IDs once
  let tagsDumped = false;

  return (tree) => {
    if (!tagsDumped) {
      console.log('\n=== ALL AVAILABLE TAGS ===');
      for (const [name, tag] of Object.entries(tags)) {
        if (tag && tag.id !== undefined) {
          console.log(`  ${name}: ${tag.id}`);
        }
      }
      // Check specific IDs
      console.log('\nLooking for tag 85:', Object.entries(tags).find(([n, t]) => t?.id === 85)?.[0] || 'NOT FOUND');
      console.log('Looking for tag 87:', Object.entries(tags).find(([n, t]) => t?.id === 87)?.[0] || 'NOT FOUND');
      tagsDumped = true;
    }

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

      console.log('\n=== HIGHLIGHT CALLBACK TEST ===');
      console.log('Code starts with:', codeText.slice(0, 50));

      highlightTree(parseTree, highlighter, (from, to, classes) => {
        const text = codeText.slice(from, to);
        console.log(`highlightTree callback: [${from}-${to}] "${text}" -> ${classes || 'NO CLASS'}`);

        if (from > lastPos) {
          const gapText = codeText.slice(lastPos, from);
          console.log(`  GAP before: [${lastPos}-${from}] "${gapText}"`);
          if (gapText) {
            const tokenRegex = /(\w+|[;,&*()[\].]|\s+|.)/g;
            let match;

            while ((match = tokenRegex.exec(gapText)) !== null) {
              const token = match[0];

              if (/^\s+$/.test(token)) {
                highlightedChildren.push({
                  type: 'text',
                  value: token
                });
              } else if (/^[;,&*()[\].]$/.test(token)) {
                highlightedChildren.push({
                  type: 'element',
                  tagName: 'span',
                  properties: { className: ['token-punctuation'] },
                  children: [{ type: 'text', value: token }]
                });
              } else {
                highlightedChildren.push({
                  type: 'element',
                  tagName: 'span',
                  properties: {},
                  children: [{ type: 'text', value: token }]
                });
              }
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

      console.log(`Final lastPos: ${lastPos}, codeText.length: ${codeText.length}`);

      if (lastPos < codeText.length) {
        const text = codeText.slice(lastPos);
        console.log(`Remaining text after all callbacks: "${text}"`);
        if (text) {
          highlightedChildren.push({ type: 'text', value: text });
        }
      }

      codeNode.children = highlightedChildren;
    });
  };
}
