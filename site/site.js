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

for (const pre of document.querySelectorAll("main pre:not(.term pre)")) {
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

const TOUR = [
  { title: "Welcome to Acxelin Quantum", text: "We make the systems you already run safe against future quantum computers. This short tour shows each part of this page in ten steps; use Next or the arrow keys, and Esc to leave." },
  { target: "header.top .wrap", title: "Find your way", text: "The menu takes you to the products, how a project starts, the readiness grades, how to try it, common questions and the full manual. Wolf Pack CBOM has its own page." },
  { target: ".hero .actions", title: "The quickest start", text: "Book a free readiness scan: it grades your public TLS and SSH endpoints and tells you what to fix first. Or watch the suite work on your own computer in a minute." },
  { target: ".hero .report", title: "What a scan gives you", text: "An example readiness report. Each endpoint gets a grade from A to C, with the algorithms it offers, so you can see which traffic could be recorded now and decrypted later." },
  { target: "#why h2", title: "Why it matters now", text: "Traffic recorded today can be decrypted once quantum computers are large enough, and regulators have set dates: 2030 to move away from RSA and elliptic curves, 2035 when they are disallowed." },
  { target: "#products h2", title: "The four products", text: "TLS 1.3 edges for your web services, VPN tunnels for sites and laptops, Vault for backups, and Readiness to measure progress. All four share one certificate authority." },
  { target: "#also-title", title: "Wolf Pack CBOM", text: "A separate tool that finds the cryptography inside your own source code, configuration and keys, and ranks what to change first." },
  { target: "#plan h2", title: "How a project starts", text: "A typical first two weeks: a readiness scan, your own certificate authority, one service behind the edge, then the VPN and backups, and finally a second scan with an evidence report for audit." },
  { target: "#use h2", title: "Try it yourself", text: "For your engineers: a one-minute Docker demo, how to install the suite, and the documentation. Everything runs on your own machines and needs no account with us." },
  { target: "#contact h2", title: "Talk to us", text: "Book the free readiness scan here. You can replay this tour any time from the button at the top of the page." },
];
const tourButton = document.getElementById("tour");
if (tourButton && typeof Tour !== "undefined") {
  tourButton.addEventListener("click", () => Tour.start("site", TOUR));
  Tour.offer("site", TOUR);
}
