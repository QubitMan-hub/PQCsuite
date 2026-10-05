/* Acxelin guided tour: step-by-step pop-ups that point at each part of a page. Shared by the website, the console and the
   VPN window. Tour.offer(name, steps) starts once for newcomers; Tour.start(name, steps) replays it. A step is
   {target: CSS selector or null for a centred card, title, text, before: optional function run first (may return a promise)}. */
const Tour = (() => {
  const CSS = `
.tour-spot{position:fixed;z-index:9998;border-radius:12px;box-shadow:0 0 0 9999px rgba(12,17,24,.62),0 0 0 3px #ffbf00;pointer-events:none}
.tour-spot.none{top:50%;left:50%;width:0;height:0;box-shadow:0 0 0 9999px rgba(12,17,24,.62)}
.tour-card{position:fixed;z-index:9999;width:min(360px,calc(100vw - 32px));background:#fff;color:#2e3c4e;border-radius:14px;overflow:hidden;
  box-shadow:0 24px 60px -12px rgba(12,17,24,.55);font:14px/1.55 "Segoe UI",system-ui,-apple-system,Roboto,sans-serif;transition:opacity .2s ease}
.tour-card.away{opacity:0;pointer-events:none}
.tour-card::before{content:"";display:block;height:4px;background:#ffbf00}
.tour-in{padding:18px 20px 16px;display:grid;gap:8px}
.tour-step{margin:0;font-size:11px;font-weight:700;letter-spacing:.12em;text-transform:uppercase;color:#8a6100}
.tour-card h2{margin:0;font:600 19px/1.25 "Host Grotesk","Segoe UI",system-ui,sans-serif;letter-spacing:-.01em;color:#1f2a37}
.tour-card p.t{margin:0;color:#3f4c59}
.tour-dots{display:flex;gap:5px;margin-top:4px}
.tour-dots i{width:7px;height:7px;border-radius:50%;background:#e6e0d2}
.tour-dots i.on{background:#ffbf00;width:18px;border-radius:4px}
.tour-bar{display:flex;align-items:center;gap:8px;margin-top:6px}
.tour-bar .sp{flex:1}
.tour-card button{font:inherit;font-weight:600;font-size:14px;border-radius:8px;padding:8px 14px;cursor:pointer;border:1px solid #e6e0d2;background:#fff;color:#2e3c4e}
.tour-card button.go{background:#ffbf00;border-color:#ffbf00;color:#111}
.tour-card button.skip{border:0;background:none;padding:8px 4px;color:#5a646f;font-weight:500;white-space:nowrap}
.tour-card button:focus-visible{outline:2px solid #1a73e8;outline-offset:2px}
@media (max-width:520px){.tour-card{left:16px!important;right:16px;bottom:16px;top:auto!important;width:auto}}
@media (prefers-reduced-motion:reduce){.tour-spot,.tour-card{transition:none}}`;
  let active = null;

  const seen = (name) => { try { return localStorage.getItem("acxelin-tour-" + name) === "done"; } catch (e) { return false; } };
  const remember = (name) => { try { localStorage.setItem("acxelin-tour-" + name, "done"); return seen(name); } catch (e) { return false; } };
  const still = matchMedia("(prefers-reduced-motion: reduce)");

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text) n.textContent = text;
    return n;
  }

  function end(done) {
    if (!active) return;
    const { name, spot, card, keys, place, back } = active;
    spot.remove(); card.remove();
    removeEventListener("keydown", keys, true); removeEventListener("resize", follow); removeEventListener("scroll", follow, true);
    if (done !== false) remember(name);
    active = null;
    if (back && back.focus) back.focus();
  }

  async function show(i) {
    if (!active || active.moving) return;
    const { steps, spot, card } = active;
    const step = steps[i];
    active.i = i;
    active.moving = true;  // a second click while a step opens its page would replay the step before
    try {
      if (step.before) await step.before();
    } finally {
      if (active) active.moving = false;
    }
    if (!active) return;
    let target = step.target ? document.querySelector(step.target) : null;
    if (target && !target.getClientRects().length) target = null;
    active.target = target;
    if (target) {
      const r = target.getBoundingClientRect();
      if (r.top < 72 || r.bottom > innerHeight - 72) {  // off screen: fade the card, scroll smoothly with the highlight following, then show it
        card.classList.add("away");
        active.moving = true;  // its old buttons must not replay a step while it travels
        target.scrollIntoView({ block: "center", behavior: still.matches ? "auto" : "smooth" });
        await settled(target);
        if (!active) return;
        active.moving = false;
      }
    }
    card.replaceChildren();
    const inner = el("div", "tour-in");
    const title = el("h2", null, step.title);
    title.id = "tour-title";
    const dots = el("div", "tour-dots");
    steps.forEach((_, k) => dots.append(el("i", k === i ? "on" : "")));
    const bar = el("div", "tour-bar");
    const skip = el("button", "skip", i === steps.length - 1 ? "" : "Skip tour");
    const prev = el("button", null, "Back");
    const next = el("button", "go", i === steps.length - 1 ? "Finish" : "Next");
    [skip, prev, next].forEach((b) => (b.type = "button"));
    skip.onclick = () => end();
    prev.onclick = () => show(i - 1);
    next.onclick = () => (i === steps.length - 1 ? end() : show(i + 1));
    if (!skip.textContent) skip.hidden = true;
    prev.hidden = i === 0;
    bar.append(skip, el("span", "sp"), prev, next);
    inner.append(el("p", "tour-step", `Step ${i + 1} of ${steps.length}`), title, el("p", "t", step.text), dots, bar);
    card.append(inner);
    spot.classList.toggle("none", !target);
    place();
    card.classList.remove("away");
    next.focus({ preventScroll: true });
  }

  function settled(target) {  // resolves once the target has stopped moving for a few frames, or after a second
    return new Promise((resolve) => {
      const began = performance.now();
      let last = null, calm = 0;
      const frame = () => {
        if (!active) return resolve();
        const top = target.getBoundingClientRect().top;
        calm = top === last ? calm + 1 : 0;
        last = top;
        placeSpot();
        if (calm >= 5 || performance.now() - began > 1000) resolve();
        else requestAnimationFrame(frame);
      };
      requestAnimationFrame(frame);
    });
  }

  function placeSpot() {
    if (!active || !active.target) return;
    const r = active.target.getBoundingClientRect(), pad = 6;
    Object.assign(active.spot.style, { left: r.left - pad + "px", top: r.top - pad + "px", width: r.width + pad * 2 + "px", height: r.height + pad * 2 + "px" });
  }

  let queued = false;
  function follow() {  // scrolling or resizing while a step is open: move with the page once per frame
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => { queued = false; place(); });
  }

  function place() {
    if (!active) return;
    const { card, target } = active;
    const pad = 6, gap = 14, w = card.offsetWidth, h = card.offsetHeight;
    if (!target) {
      Object.assign(card.style, { left: (innerWidth - w) / 2 + "px", top: Math.max(16, (innerHeight - h) / 2) + "px" });
      return;
    }
    const r = target.getBoundingClientRect();
    placeSpot();
    if (r.width < 320 && r.left < innerWidth / 3 && r.right + gap + w + 16 < innerWidth && innerWidth > 520) {  // beside a sidebar entry
      Object.assign(card.style, { left: r.right + pad + gap + "px", top: Math.min(Math.max(8, r.top + r.height / 2 - h / 2), innerHeight - h - 8) + "px" });
      return;
    }
    const below = r.bottom + pad + gap, above = r.top - pad - gap - h;
    const top = below + h < innerHeight - 8 ? below : above > 8 ? above : Math.max(8, innerHeight - h - 16);
    const left = Math.min(Math.max(16, r.left + r.width / 2 - w / 2), innerWidth - w - 16);
    Object.assign(card.style, { left: left + "px", top: top + "px" });
  }

  function start(name, steps) {
    end(false);
    if (!document.getElementById("tour-css")) {
      const s = el("style"); s.id = "tour-css"; s.textContent = CSS; document.head.append(s);
    }
    const spot = el("div", "tour-spot none"), card = el("div", "tour-card");
    card.setAttribute("role", "dialog"); card.setAttribute("aria-modal", "true"); card.setAttribute("aria-labelledby", "tour-title");
    document.body.append(spot, card);
    const keys = (e) => {
      if (!active) return;
      if (e.key === "Escape") { e.preventDefault(); end(); }
      else if (e.key === "ArrowRight") { e.preventDefault(); active.i < steps.length - 1 ? show(active.i + 1) : end(); }
      else if (e.key === "ArrowLeft" && active.i > 0) { e.preventDefault(); show(active.i - 1); }
      else if (e.key === "Tab") {
        const b = [...card.querySelectorAll("button:not([hidden])")];
        const k = b.indexOf(document.activeElement);
        e.preventDefault();
        b[(k + (e.shiftKey ? b.length - 1 : 1)) % b.length].focus();
      }
    };
    active = { name, steps, spot, card, keys, place, i: 0, back: document.activeElement };
    addEventListener("keydown", keys, true); addEventListener("resize", follow); addEventListener("scroll", follow, true);
    show(0);
  }

  function offer(name, steps) {
    // once per browser, counted when it first appears; where nothing can be remembered it never starts by itself,
    // since it would return on every visit. Automated browsers are not newcomers.
    if (!seen(name) && !navigator.webdriver && remember(name)) start(name, steps);
  }

  return { start, offer, end, seen };
})();
