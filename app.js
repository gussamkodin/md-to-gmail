const markdownInput = document.querySelector("#markdownInput");
const subjectInput = document.querySelector("#subjectInput");
const preview = document.querySelector("#preview");
const clearBtn = document.querySelector("#clearBtn");
const copyLabelBtn = document.querySelector("#copyLabelBtn");
const copyGmailBtn = document.querySelector("#copyGmailBtn");
const toast = document.querySelector("#toast");
const charCount = document.querySelector("#charCount");

const sampleSubject = "Reflected XSS";
const sampleReport = `## Summary
Reflected XSS found on the search endpoint.

## Impact
- Account takeover risk through session actions
- Phishing through trusted domain
- User data exposure

| Field | Value |
| --- | --- |
| Severity | High |
| Affected endpoint | /search |

## Steps to Reproduce
1. Login as a normal user
2. Open the vulnerable URL
3. Inject the payload

\`\`\`
https://example.com/search?q=<script>alert(document.domain)</script>
\`\`\`

## Remediation
Encode user-controlled output and enforce a strict Content Security Policy.`;

function escapeHtml(value) {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function inlineMarkdown(value) {
  let html = escapeHtml(value);
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*([^*]+)\*/g, "<em>$1</em>");
  html = html.replace(/\[([^\]]+)\]\((https?:\/\/[^)]+)\)/g, '<a href="$2">$1</a>');
  return html;
}

function renderTable(tableBuffer) {
  const rows = tableBuffer
    .map((row) => row.trim().replace(/^\||\|$/g, "").split("|").map((cell) => cell.trim()))
    .filter((row) => !row.every((cell) => /^:?-{3,}:?$/.test(cell)));

  if (!rows.length) return "";

  const [head, ...body] = rows;
  let html = "<table><thead><tr>";
  head.forEach((cell) => {
    html += `<th>${inlineMarkdown(cell)}</th>`;
  });
  html += "</tr></thead><tbody>";
  body.forEach((row) => {
    html += "<tr>";
    row.forEach((cell) => {
      html += `<td>${inlineMarkdown(cell)}</td>`;
    });
    html += "</tr>";
  });
  html += "</tbody></table>";
  return html;
}

function renderMarkdown(markdown) {
  const lines = markdown.replace(/\r\n/g, "\n").split("\n");
  const html = [];
  let listOpen = false;
  let orderedOpen = false;
  let codeOpen = false;
  let codeBuffer = [];
  let tableBuffer = [];

  function closeList() {
    if (listOpen) {
      html.push("</ul>");
      listOpen = false;
    }
    if (orderedOpen) {
      html.push("</ol>");
      orderedOpen = false;
    }
  }

  function closeCode() {
    if (codeOpen) {
      html.push(`<pre><code>${escapeHtml(codeBuffer.join("\n"))}</code></pre>`);
      codeOpen = false;
      codeBuffer = [];
    }
  }

  function closeTable() {
    if (tableBuffer.length) {
      html.push(renderTable(tableBuffer));
      tableBuffer = [];
    }
  }

  for (const line of lines) {
    if (line.trim().startsWith("```")) {
      if (codeOpen) {
        closeCode();
      } else {
        closeList();
        closeTable();
        codeOpen = true;
        codeBuffer = [];
      }
      continue;
    }

    if (codeOpen) {
      codeBuffer.push(line);
      continue;
    }

    if (line.includes("|") && /^\s*\|?.+\|.+\|?\s*$/.test(line)) {
      closeList();
      tableBuffer.push(line);
      continue;
    }

    closeTable();

    if (!line.trim()) {
      closeList();
      continue;
    }

    const heading = line.match(/^(#{1,3})\s+(.+)$/);
    if (heading) {
      closeList();
      const level = heading[1].length;
      html.push(`<h${level}>${inlineMarkdown(heading[2])}</h${level}>`);
      continue;
    }

    const bullet = line.match(/^\s*[-*]\s+(.+)$/);
    if (bullet) {
      if (orderedOpen) {
        html.push("</ol>");
        orderedOpen = false;
      }
      if (!listOpen) {
        html.push("<ul>");
        listOpen = true;
      }
      html.push(`<li>${inlineMarkdown(bullet[1])}</li>`);
      continue;
    }

    const numbered = line.match(/^\s*\d+\.\s+(.+)$/);
    if (numbered) {
      if (listOpen) {
        html.push("</ul>");
        listOpen = false;
      }
      if (!orderedOpen) {
        html.push("<ol>");
        orderedOpen = true;
      }
      html.push(`<li>${inlineMarkdown(numbered[1])}</li>`);
      continue;
    }

    const quote = line.match(/^\s*>\s?(.+)$/);
    if (quote) {
      closeList();
      html.push(`<blockquote>${inlineMarkdown(quote[1])}</blockquote>`);
      continue;
    }

    closeList();
    html.push(`<p>${inlineMarkdown(line)}</p>`);
  }

  closeCode();
  closeTable();
  closeList();
  return html.join("");
}

function markdownToText(markdown) {
  return markdown
    .replace(/\r\n/g, "\n")
    .replace(/^#{1,6}\s+/gm, "")
    .replace(/^\s*[-*]\s+/gm, "- ")
    .replace(/^\s*\d+\.\s+/gm, "- ")
    .replace(/```[\s\S]*?```/g, (block) => block.replace(/```/g, "").trim())
    .replace(/\*\*([^*]+)\*\*/g, "$1")
    .replace(/\*([^*]+)\*/g, "$1")
    .replace(/`([^`]+)`/g, "$1")
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

function getSubject() {
  const typedSubject = subjectInput.value.trim();
  if (typedSubject) return typedSubject;

  const firstHeading = markdownInput.value.match(/^#\s+(.+)$/m);
  return firstHeading ? firstHeading[1].trim() : "";
}

function updatePreview() {
  const value = markdownInput.value;
  const renderedBody = value.trim() ? renderMarkdown(value) : "<p>Hasil convert akan muncul di sini.</p>";
  const subject = getSubject();
  preview.innerHTML = subject
    ? `<h1>${escapeHtml(subject)}</h1>${renderedBody}`
    : renderedBody;
  charCount.textContent = `${value.length} chars`;
}

function showToast(message) {
  toast.textContent = message;
  toast.classList.add("show");
  window.setTimeout(() => toast.classList.remove("show"), 1300);
}

async function copyLabel() {
  const subject = getSubject();
  await navigator.clipboard.writeText(subject);
  showToast("Label copied");
}

async function copyPlainText() {
  const subject = getSubject();
  const body = markdownToText(markdownInput.value);
  await navigator.clipboard.writeText([subject, body].filter(Boolean).join("\n\n"));
  showToast("Plain text copied");
}

function styleForTag(tagName) {
  const tag = tagName.toLowerCase();
  const styles = {
    h1: "margin:0 0 14px;padding:0;color:#111827;font-family:Arial,Helvetica,sans-serif;font-size:16px;line-height:1.3;font-weight:700;overflow-wrap:anywhere;word-break:break-word;",
    h2: "margin:18px 0 8px;color:#111827;font-family:Arial,Helvetica,sans-serif;font-size:14px;line-height:1.35;font-weight:700;overflow-wrap:anywhere;word-break:break-word;",
    h3: "margin:14px 0 6px;color:#334155;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.35;font-weight:700;overflow-wrap:anywhere;word-break:break-word;",
    p: "margin:0 0 12px;color:#172033;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.62;overflow-wrap:anywhere;word-break:break-word;",
    ul: "margin:0 0 14px 20px;padding:0;color:#172033;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.62;overflow-wrap:anywhere;word-break:break-word;",
    ol: "margin:0 0 14px 20px;padding:0;color:#172033;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.62;overflow-wrap:anywhere;word-break:break-word;",
    li: "margin:4px 0;color:#172033;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.62;overflow-wrap:anywhere;word-break:break-word;",
    code: "border:1px solid #dbe2ee;border-radius:5px;background:#f3f6fb;color:#0f172a;font-family:Consolas,Menlo,monospace;font-size:13px;padding:1px 5px;white-space:normal;overflow-wrap:anywhere;word-break:break-word;",
    pre: "margin:12px 0 16px;border:1px solid #dbe2ee;border-radius:8px;background:#f8fafc;padding:12px 14px;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;color:#0f172a;font-family:Consolas,Menlo,monospace;font-size:13px;line-height:1.5;max-width:100%;",
    blockquote: "margin:12px 0 16px;color:#475569;padding:0;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.62;overflow-wrap:anywhere;word-break:break-word;",
    table: "width:100%;max-width:100%;margin:12px 0 16px;border-collapse:collapse;table-layout:fixed;color:#172033;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.5;",
    th: "border:1px solid #dbe2ee;background:#eef6f5;color:#0f172a;padding:8px 10px;text-align:left;vertical-align:top;font-weight:700;overflow-wrap:anywhere;word-break:break-word;",
    td: "border:1px solid #dbe2ee;color:#172033;padding:8px 10px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word;",
    a: "color:#0f766e;text-decoration:underline;",
    strong: "font-weight:700;",
    em: "font-style:italic;"
  };
  return styles[tag] || "";
}

function buildInlineGmailHtml() {
  const wrapper = document.createElement("div");
  wrapper.innerHTML = markdownInput.value.trim()
    ? renderMarkdown(markdownInput.value)
    : "<p>Hasil convert akan muncul di sini.</p>";
  wrapper.setAttribute("style", "width:100%;max-width:100%;color:#172033;font-family:Arial,Helvetica,sans-serif;font-size:13px;line-height:1.62;overflow-wrap:anywhere;word-break:break-word;");

  wrapper.querySelectorAll("*").forEach((node) => {
    const style = styleForTag(node.tagName);
    if (style) node.setAttribute("style", style);
    if (node.tagName.toLowerCase() === "pre") {
      node.querySelectorAll("code").forEach((code) => {
        code.setAttribute("style", "border:0;background:transparent;color:#0f172a;font-family:Consolas,Menlo,monospace;font-size:13px;padding:0;white-space:pre-wrap;overflow-wrap:anywhere;word-break:break-word;");
      });
    }
  });

  return wrapper.outerHTML;
}

async function writeRichClipboard() {
  const html = buildInlineGmailHtml();
  const body = markdownToText(markdownInput.value);
  const text = body;

  if (navigator.clipboard && window.ClipboardItem) {
    const item = new ClipboardItem({
      "text/html": new Blob([html], { type: "text/html" }),
      "text/plain": new Blob([text], { type: "text/plain" })
    });
    await navigator.clipboard.write([item]);
  } else {
    const range = document.createRange();
    const temp = document.createElement("div");
    temp.innerHTML = html;
    temp.style.position = "fixed";
    temp.style.left = "-9999px";
    document.body.appendChild(temp);
    range.selectNodeContents(temp);
    const selection = window.getSelection();
    selection.removeAllRanges();
    selection.addRange(range);
    document.execCommand("copy");
    selection.removeAllRanges();
    temp.remove();
  }
}

async function copyGmailHtml() {
  await writeRichClipboard();
  showToast("Gmail-ready copy done");
}

async function openGmailCompose() {
  const subject = getSubject();
  const body = markdownToText(markdownInput.value);
  const params = new URLSearchParams({
    view: "cm",
    fs: "1",
    tf: "1",
    su: subject,
    body
  });
  const url = `https://mail.google.com/mail/?${params.toString()}`;
  window.open(url, "_blank");
  writeRichClipboard()
    .then(() => showToast("Rich report copied, Gmail opened"))
    .catch(() => showToast("Gmail opened"));
}

function initApp() {
  subjectInput.value = sampleSubject;
  markdownInput.value = sampleReport;
  subjectInput.addEventListener("input", updatePreview);
  markdownInput.addEventListener("input", updatePreview);
  clearBtn.addEventListener("click", () => {
    subjectInput.value = "";
    markdownInput.value = "";
    updatePreview();
    subjectInput.focus();
  });
  copyLabelBtn.addEventListener("click", copyLabel);
  copyGmailBtn.addEventListener("click", copyGmailHtml);
  updatePreview();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initApp);
} else {
  initApp();
}
