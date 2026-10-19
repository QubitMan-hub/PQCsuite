/* Shared by every console page: `backticks` in a message show as code, and table cells carry their column name for the stacked phone layout. */
const acxText = (s) => String(s ?? "").split("`").map((part, i) => { if (i % 2 === 0) return document.createTextNode(part); const c = document.createElement("code"); c.textContent = part; return c; });
new MutationObserver(() => {
  for (const t of document.querySelectorAll(".scroll table")) {
    const heads = [...(t.tHead ? t.tHead.rows[0].cells : [])].map((c) => c.textContent);
    for (const r of t.tBodies[0] ? t.tBodies[0].rows : []) [...r.cells].forEach((c, i) => { if (heads[i] && c.dataset.label !== heads[i]) c.dataset.label = heads[i]; });
  }
}).observe(document.body, {childList: true, subtree: true});
