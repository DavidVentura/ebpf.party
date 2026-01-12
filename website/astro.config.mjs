// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import react from '@astrojs/react';
import tailwind from '@astrojs/tailwind';
import rehypeLezerHighlight from './src/lib/rehype-lezer-highlight.js';

// https://astro.build/config
export default defineConfig({
  integrations: [mdx(), react(), tailwind()],
  markdown: {
    syntaxHighlight: false,
    rehypePlugins: [rehypeLezerHighlight],
  },
  vite: {
    worker: {
      format: 'es'
    },
    server: {
      allowedHosts: ['ebpf.party']
    },
    build: {
      rollupOptions: {
        output: {
          manualChunks: (id) => {
            if (id.includes('node_modules')) {
              if (id.includes('react') || id.includes('react-dom')) {
                return 'vendor-react';
              }
              if (id.includes('@codemirror') || id.includes('@uiw/react-codemirror')) {
                return 'vendor-codemirror';
              }
              if (id.includes('react-resizable-panels')) {
                return 'vendor-panels';
              }
              if (id.includes('syntax_check')) {
                return 'vendor-wasm';
              }
            }
          }
        }
      }
    }
  }
});
