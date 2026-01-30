import { z } from 'zod';

export const exportHtmlSchema = z.object({
  title: z.string().describe('Report title'),
  content: z.string().describe('Markdown content to convert'),
  theme: z.enum(['light', 'dark', 'security']).default('security')
    .describe('Visual theme'),
  includeStyles: z.boolean().default(true).describe('Include embedded CSS')
});

export type ExportHtmlInput = z.infer<typeof exportHtmlSchema>;

const themes = {
  light: {
    bg: '#ffffff',
    text: '#1a1a1a',
    heading: '#0066cc',
    border: '#e0e0e0',
    codeBg: '#f5f5f5',
    critical: '#dc3545',
    high: '#fd7e14',
    medium: '#ffc107',
    low: '#17a2b8',
    info: '#6c757d'
  },
  dark: {
    bg: '#1a1a2e',
    text: '#e0e0e0',
    heading: '#4da6ff',
    border: '#404060',
    codeBg: '#2d2d44',
    critical: '#ff6b6b',
    high: '#ffa94d',
    medium: '#ffd43b',
    low: '#4dabf7',
    info: '#868e96'
  },
  security: {
    bg: '#0d1117',
    text: '#c9d1d9',
    heading: '#58a6ff',
    border: '#30363d',
    codeBg: '#161b22',
    critical: '#f85149',
    high: '#db6d28',
    medium: '#d29922',
    low: '#3fb950',
    info: '#8b949e'
  }
};

export function exportHtml(input: ExportHtmlInput): {
  success: boolean;
  html: string;
} {
  const { title, content, theme, includeStyles } = input;
  const colors = themes[theme];

  const htmlContent = markdownToHtml(content, colors);

  const styles = includeStyles ? `
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }
      body {
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        background: ${colors.bg};
        color: ${colors.text};
        line-height: 1.6;
        padding: 2rem;
        max-width: 1200px;
        margin: 0 auto;
      }
      h1, h2, h3, h4 { color: ${colors.heading}; margin: 1.5rem 0 1rem; }
      h1 { font-size: 2rem; border-bottom: 2px solid ${colors.border}; padding-bottom: 0.5rem; }
      h2 { font-size: 1.5rem; border-bottom: 1px solid ${colors.border}; padding-bottom: 0.3rem; }
      h3 { font-size: 1.25rem; }
      p { margin: 0.75rem 0; }
      ul, ol { margin: 0.75rem 0; padding-left: 2rem; }
      li { margin: 0.25rem 0; }
      code {
        background: ${colors.codeBg};
        padding: 0.2rem 0.4rem;
        border-radius: 3px;
        font-family: 'Fira Code', 'Consolas', monospace;
        font-size: 0.9em;
      }
      pre {
        background: ${colors.codeBg};
        padding: 1rem;
        border-radius: 6px;
        overflow-x: auto;
        margin: 1rem 0;
      }
      pre code { padding: 0; background: none; }
      table {
        width: 100%;
        border-collapse: collapse;
        margin: 1rem 0;
      }
      th, td {
        padding: 0.75rem;
        border: 1px solid ${colors.border};
        text-align: left;
      }
      th { background: ${colors.codeBg}; }
      a { color: ${colors.heading}; text-decoration: none; }
      a:hover { text-decoration: underline; }
      .severity-critical { color: ${colors.critical}; font-weight: bold; }
      .severity-high { color: ${colors.high}; font-weight: bold; }
      .severity-medium { color: ${colors.medium}; font-weight: bold; }
      .severity-low { color: ${colors.low}; font-weight: bold; }
      .severity-info { color: ${colors.info}; }
      .badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-size: 0.8rem;
        font-weight: bold;
      }
      .badge-critical { background: ${colors.critical}; color: white; }
      .badge-high { background: ${colors.high}; color: white; }
      .badge-medium { background: ${colors.medium}; color: black; }
      .badge-low { background: ${colors.low}; color: white; }
      hr { border: none; border-top: 1px solid ${colors.border}; margin: 2rem 0; }
      blockquote {
        border-left: 4px solid ${colors.heading};
        padding-left: 1rem;
        margin: 1rem 0;
        color: ${colors.info};
      }
      .header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
      }
      .timestamp { color: ${colors.info}; font-size: 0.9rem; }
      .summary-box {
        background: ${colors.codeBg};
        border: 1px solid ${colors.border};
        border-radius: 8px;
        padding: 1rem;
        margin: 1rem 0;
      }
      @media print {
        body { background: white; color: black; }
        .no-print { display: none; }
      }
    </style>
  ` : '';

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <meta name="generator" content="mcp-vanguard">
  <title>${escapeHtml(title)}</title>
  ${styles}
</head>
<body>
  <div class="header">
    <div>
      <h1>${escapeHtml(title)}</h1>
    </div>
    <div class="timestamp">
      Generated: ${new Date().toISOString()}
    </div>
  </div>

  <main>
    ${htmlContent}
  </main>

  <footer style="margin-top: 3rem; padding-top: 1rem; border-top: 1px solid ${colors.border}; text-align: center; color: ${colors.info};">
    <p>Generated by mcp-vanguard</p>
  </footer>
</body>
</html>`;

  return {
    success: true,
    html
  };
}

function markdownToHtml(markdown: string, colors: typeof themes.light): string {
  let html = markdown;

  html = html.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  html = html.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  html = html.replace(/^# (.+)$/gm, '<h1>$1</h1>');

  html = html.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  html = html.replace(/\*(.+?)\*/g, '<em>$1</em>');
  html = html.replace(/`([^`]+)`/g, '<code>$1</code>');

  html = html.replace(/```(\w*)\n([\s\S]*?)```/g, (_, lang, code) => {
    return `<pre><code class="language-${lang}">${escapeHtml(code.trim())}</code></pre>`;
  });

  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>');

  html = html.replace(/^\| (.+) \|$/gm, (match, content) => {
    const cells = content.split(' | ').map((cell: string) => cell.trim());
    if (cells.every((c: string) => /^[-:]+$/.test(c))) {
      return '';
    }
    const isHeader = match.includes('---');
    const tag = isHeader ? 'th' : 'td';
    return `<tr>${cells.map((c: string) => `<${tag}>${processSeverity(c, colors)}</${tag}>`).join('')}</tr>`;
  });

  html = html.replace(/(<tr>[\s\S]*?<\/tr>[\s\n]*)+/g, (match) => {
    if (match.includes('<th>')) {
      return `<table><thead>${match.split('</tr>')[0]}</tr></thead><tbody>${match.split('</tr>').slice(1).join('</tr>')}</tbody></table>`;
    }
    return `<table>${match}</table>`;
  });

  html = html.replace(/^- (.+)$/gm, '<li>$1</li>');
  html = html.replace(/(<li>.*<\/li>\n?)+/g, '<ul>$&</ul>');

  html = html.replace(/^\d+\. (.+)$/gm, '<li>$1</li>');

  html = html.replace(/^---$/gm, '<hr>');

  html = html.replace(/^(?!<[a-z]|$)(.+)$/gm, '<p>$1</p>');

  html = html.replace(/<p><\/p>/g, '');
  html = html.replace(/\n{3,}/g, '\n\n');

  return html;
}

function processSeverity(text: string, colors: typeof themes.light): string {
  return text
    .replace(/🔴\s*(Critical)/gi, `<span class="badge badge-critical">$1</span>`)
    .replace(/🟠\s*(High)/gi, `<span class="badge badge-high">$1</span>`)
    .replace(/🟡\s*(Medium)/gi, `<span class="badge badge-medium">$1</span>`)
    .replace(/🔵\s*(Low)/gi, `<span class="badge badge-low">$1</span>`)
    .replace(/⚪\s*(Info)/gi, `<span class="badge" style="background: ${colors.info}; color: white;">$1</span>`)
    .replace(/CRITICAL/g, '<span class="severity-critical">CRITICAL</span>')
    .replace(/HIGH/g, '<span class="severity-high">HIGH</span>')
    .replace(/MEDIUM/g, '<span class="severity-medium">MEDIUM</span>')
    .replace(/LOW/g, '<span class="severity-low">LOW</span>');
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
