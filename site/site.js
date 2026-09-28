const bar = document.querySelector(".top");
const nav = bar.querySelector("nav");
const menu = bar.querySelector(".menu");

const setOpen = open => {
  menu.setAttribute("aria-expanded", open);
  bar.classList.toggle("open", open);
};
menu.addEventListener("click", () => setOpen(menu.getAttribute("aria-expanded") !== "true"));
nav.addEventListener("click", e => e.target.closest("a") && setOpen(false));
addEventListener("keydown", e => e.key === "Escape" && setOpen(false));
addEventListener("scroll", () => bar.classList.toggle("scrolled", scrollY > 8), { passive: true });

const links = [...nav.querySelectorAll('a[href^="#"]:not(.btn)')];
const spy = new IntersectionObserver(entries => {
  for (const e of entries) {
    if (!e.isIntersecting) continue;
    for (const a of links) a.hash === "#" + e.target.id ? a.setAttribute("aria-current", "true") : a.removeAttribute("aria-current");
  }
}, { rootMargin: "-40% 0px -55% 0px" });
for (const a of links) {
  const s = document.getElementById(a.hash.slice(1));
  if (s) spy.observe(s);
}

for (const pre of document.querySelectorAll("main pre")) {
  const box = document.createElement("div");
  const b = document.createElement("button");
  box.className = "code";
  b.type = "button";
  b.className = "copy";
  b.textContent = "Copy";
  b.setAttribute("aria-label", "Copy to clipboard");
  b.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(pre.innerText);
      b.textContent = "Copied";
    } catch {
      const r = document.createRange();
      r.selectNodeContents(pre);
      getSelection().removeAllRanges();
      getSelection().addRange(r);
      b.textContent = "Selected";
    }
    setTimeout(() => (b.textContent = "Copy"), 1600);
  });
  pre.tabIndex = 0;
  pre.before(box);
  box.append(pre, b);
}

const finder = document.getElementById("finder");
if (finder) {
  const STEPS = {
    readiness: ["Readiness assessment", "#readiness", "Grade your public TLS and SSH endpoints to see what is exposed today."],
    tls: ["TLS 1.3 + mTLS", "#tls", "Put the post-quantum edge in front of one API or database, in transition mode so nobody is locked out."],
    vpn: ["IPsec VPN", "#vpn", "Join two sites over the hybrid ML-KEM tunnel, then move remote staff to WireGuard."],
    vault: ["Vault", "#vault", "Point your nightly backup job at Vault, so archives stay safe for their whole retention period."],
    wolf: ["Wolf Pack CBOM", "wolf-pack.html", "Scan one repository to see which algorithms your own code uses, ranked by what to migrate first.", "Also from Acxelin"],
    evidence: ["Evidence report", "#readiness", "Give audit a report that maps each finding to the NIST IR 8547 and CNSA 2.0 dates."],
  };
  const list = document.getElementById("steps");
  const render = () => {
    const f = new FormData(finder);
    const first = f.get("first");
    const plan = [];
    if (f.get("known") !== "yes" && first !== "readiness") plan.push("readiness");
    plan.push(first);
    if (f.get("audit") === "yes") plan.push("evidence");
    list.replaceChildren(...plan.map(k => {
      const [name, href, text, tag] = STEPS[k];
      const li = document.createElement("li");
      const a = Object.assign(document.createElement("a"), { href, textContent: name });
      li.append(...(tag ? [Object.assign(document.createElement("small"), { textContent: tag })] : []), a, Object.assign(document.createElement("p"), { textContent: text }));
      return li;
    }));
  };
  finder.addEventListener("change", render);
  render();
  document.getElementById("start").hidden = false;
}

const up = Object.assign(document.createElement("a"), { href: "#main", className: "up", textContent: "Top" });
up.setAttribute("aria-label", "Back to top");
up.hidden = true;
document.body.append(up);
addEventListener("scroll", () => (up.hidden = scrollY < 1200), { passive: true });
