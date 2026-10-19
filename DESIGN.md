---
name: Acxelin Quantum products website
description: Each product shown as a dissection of its own real output, frames you select and read.
colors:
  paper: "#f4f6f7"
  pane: "#ffffff"
  sunken: "#eaeef1"
  select: "#e1e8ee"
  ink: "#111c26"
  body: "#2c3a46"
  muted: "#56636f"
  rule: "#d3dbe1"
  rule-strong: "#9eabb6"
  amber: "#ffbf00"
  exposed: "#8a5600"
  exposed-ground: "#fff3d1"
  ok: "#17704a"
  bad: "#ad3218"
typography:
  display:
    fontFamily: "Host Grotesk, Segoe UI, system-ui, sans-serif"
    fontSize: "clamp(2.1rem, 4.6vw, 3.5rem)"
    fontWeight: 500
    lineHeight: 1.12
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "Host Grotesk, Segoe UI, system-ui, sans-serif"
    fontSize: "clamp(1.45rem, 2.6vw, 1.9rem)"
    fontWeight: 500
    lineHeight: 1.12
    letterSpacing: "-0.015em"
  title:
    fontFamily: "Host Grotesk, Segoe UI, system-ui, sans-serif"
    fontSize: "1.1rem"
    fontWeight: 600
    lineHeight: 1.12
  body:
    fontFamily: "Host Grotesk, Segoe UI, system-ui, sans-serif"
    fontSize: "1.0625rem"
    fontWeight: 400
    lineHeight: 1.6
  data:
    fontFamily: "Roboto Mono, ui-monospace, SF Mono, Menlo, Consolas, monospace"
    fontSize: "0.9rem"
    fontWeight: 400
    lineHeight: 1.45
rounded:
  sm: "4px"
  md: "6px"
  lg: "8px"
spacing:
  gutter: "clamp(16px, 4vw, 40px)"
  section: "clamp(44px, 7vw, 76px)"
  frame-row: "11px 16px"
components:
  button-primary:
    backgroundColor: "{colors.ink}"
    textColor: "{colors.paper}"
    rounded: "{rounded.md}"
    padding: "0 18px"
    height: "44px"
  button-secondary:
    backgroundColor: "{colors.pane}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "0 18px"
    height: "44px"
  capture:
    backgroundColor: "{colors.pane}"
    rounded: "{rounded.lg}"
  frame-selected:
    backgroundColor: "{colors.select}"
    textColor: "{colors.ink}"
    typography: "{typography.data}"
    padding: "{spacing.frame-row}"
---

# Design System: Acxelin Quantum products website

## Overview

**Creative North Star: "The Dissection"**

Every product page lays its own real evidence out the way a protocol analyser does: a handshake, a scan or a tunnel as numbered frames, each one selectable, with a detail tree under the selected frame. The page proves the product by showing what it did, captured when the site was built, and states what it does not claim in the same weight as what it does.

The world is cool paper and blue-black ink, hairline panes, and no decoration. Colour is a verdict and nothing else. The one texture in the system is the amber hatch, and it means one thing: quantum-exposed. Density is a working tool's: tabular rows, short sentences, numbered figures with captions.

**Key Characteristics:**
- Real build-time output as the hero, never a screenshot of a marketing mock.
- Numbered figures (Fig. 1, Fig. 2) with captions that state what the figure shows.
- Colour carries a verdict; everything else is ink on paper.
- Limits stated next to claims, as a list of the same weight.

## Colors

Ink on cool paper, with three verdict colours and the brand amber held for the exposed hatch and text selection.

### Primary
- **Blue-Black Ink** (ink): headings, strong text, the primary button, the now marker and focus rings.

### Secondary
- **Signal Amber** (amber): the brand colour. It appears as the hatch on quantum-exposed marks, as the text-selection colour, and in the logo, never as a fill for buttons or panels.

### Verdict colours
- **Negotiated Green** (ok): negotiated post-quantum, accepted. Keys, verdict text and the post-quantum hop in topology figures.
- **Refusal Red** (bad): refused, or broken today. Keys, verdict text and the assumed-quantum-computer line in the Mosca timeline.
- **Exposed Umber** (exposed) over **Exposed Wash** (exposed-ground): the text and outline that go with the amber hatch for quantum-exposed items.

### Neutral
- **Cool Paper** (paper): page ground.
- **Pane White** (pane): captures, panels and code blocks.
- **Sunken Slate** (sunken): capture bars, hover rows and inline code.
- **Selection Slate** (select): the selected frame and the current navigation item.
- **Body Slate** (body) and **Muted Slate** (muted): running text, and timestamps, captions and secondary labels.
- **Hairline** (rule) and **Strong Hairline** (rule-strong): dividers, pane borders and secondary button borders.

The dark theme redefines every token under `prefers-color-scheme: dark`, with an ink-black ground (#0d1318), paper text and lighter verdict tones (#5fd197, #ff8c74, #ffcf4d).

### Named Rules
**The Verdict Rule.** Green, red and the amber hatch each mean exactly one thing (post-quantum, refused or broken, quantum-exposed). A colour that does not carry a verdict is not used.

**The One Texture Rule.** The amber hatch is the only texture, and only on quantum-exposed items. It is never decoration.

## Typography

**Display Font:** Host Grotesk (with Segoe UI, system-ui)
**Body Font:** Host Grotesk
**Data Font:** Roboto Mono (with ui-monospace, SF Mono, Menlo, Consolas)

**Character:** A plain, slightly technical grotesk for everything a person reads, and a monospace for everything a machine printed.

### Hierarchy
- **Display** (500, clamp(2.1rem, 4.6vw, 3.5rem), 1.12, -0.025em): one page title per page, at most 22ch wide.
- **Headline** (500, clamp(1.45rem, 2.6vw, 1.9rem)): section titles.
- **Title** (600, 1.1rem): sub-sections, release panel titles, policy rungs (in mono, because a rung's title is a policy name).
- **Body** (400, 1.0625rem, 1.6): running text, at most 68ch wide; the lead runs at 1.08 to 1.22rem in ink.
- **Data** (400, 0.8 to 0.9rem): frames, trees, commands, file names, figure numbers and capture bars.

### Named Rules
**The Machine Voice Rule.** Mono is only for what a program printed or a person types: frames, commands, file names, algorithm identifiers and figure numbers. Links, buttons and prose stay in Host Grotesk.

## Layout

Single column inside a 1180px wrapper with a fluid gutter (16 to 40px). Sections are separated by one hairline and generous vertical padding. Text-led sections use a split: a heading and lede on the left, the evidence on the right (minmax(0, 1fr) by minmax(0, 1.35fr)). Product openings use the same split for the title and the release panel, with the capture full width beneath. Everything stacks to one column below 860px. Captures, tables and code scroll inside their own pane, and the page never scrolls sideways. Figures that are drawn (the Mosca timeline) ship a second, narrow drawing for phones instead of shrinking.

## Elevation & Depth

Flat. Depth comes from tonal layers (paper, pane, sunken, select) and 1px hairlines, never shadows.

**The Hairline Rule.** Separation is a 1px rule or a tonal step. No box-shadow anywhere, and no coloured side-borders.

## Shapes

Small, quiet radii: 4px for chips, inline code and Copy buttons, 6px for buttons, nodes and code blocks, and 8px for panes (captures, panels, the policy ladder). Verdict keys are 11px squares with a 2px radius.

## Components

### Buttons
- **Shape:** gently squared (6px), 44px tall.
- **Primary:** ink fill with paper text; hover lowers opacity.
- **Secondary:** pane fill, strong hairline border, ink text; the border darkens to ink on hover.
- **Copy:** a small 30px button in a row above its code block, labelled "Copy command" or "Copy output", reporting "Copied" or "Select and copy".

### Capture (signature)
- A numbered figure: a sunken bar naming the command and "captured when this site was built", with a legend of verdict keys; an ordered list of frames; a caption with the figure number.
- **Frame row:** number, timestamp or tier, what happened, and the verdict with its key, in a four-column mono grid (2.6rem, 5.4rem, 1fr, 13rem) that drops to two columns on phones.
- **Selection:** click or ArrowUp, ArrowDown, Home and End. The selected frame takes the selection slate and a small ink square (the now marker), and only its tree shows. Without script every tree shows.
- **Tree:** a term and value grid in mono, with prose values in Host Grotesk. A field with several values lists one per line under one term.

### Release panel
- Pane with hairline, 8px radius: the product and version, the archive and checksum file, a copyable verify-and-install command, and a link to the full steps.

### Topology and pipeline figures
- Nodes are panes with a strong hairline. The product's own node gets a 2px ink border. Links are mono labels over a 2px rule, green only on the post-quantum hop. On phones they stack vertically, with the rule on the left.

### Navigation
- Product name in ink and 600 weight, then that product's pages in muted text. The current page sits on the selection slate. On phones the strip scrolls sideways under the logo.

## Consoles

The TLS, Readiness and VPN administrator consoles and the VPN app window use the same tokens, fonts and verdict law. The shared rules live in `core/src/acxelin_core/assets/shell.css`; each product's page adds only its own layout. Consoles are tools, so they run denser than the website and controls stay standard.

### Console type ramp
- **Page title** (500, 24px), **section** (500, 18px), **item** (600, 15px).
- **Body** 14.5px/1.55; **labels** 13.5px in ink at 600; **lede** 15px muted.
- **Data** 13px mono: table cells holding names, serials, dates and algorithms; facts rows; textareas.
- **Small** 12 to 12.5px: table headers, pills, the brandbar hint. Nothing below 12px.

### Console components
- **Brandbar:** the logo, a hairline, the product name in ink at 600, and where the console can be opened in muted text on the right.
- **Tabs:** muted labels on a hairline; the current tab is ink with a 2px ink underline.
- **Buttons:** 40px tall (30px for `.small` buttons in table rows). Primary is ink; `.quiet` is the secondary; `.danger` (red outline) appears only on the second, confirming click of a revoke.
- **Tables:** inside a pane with an 8px radius; the header sits on the sunken band; rows take a faint selection slate on hover.
- **Pills:** 4px radius. Green for ok, red for refused or critical, the amber hatch with a hairline for quantum-exposed (`high`, grade B); `medium` (a classical fallback beside a hybrid) is an amber outline without the hatch. An operational warning that is not about quantum exposure is an ink outline. Everything else is neutral.
- **Tables on phones:** below 560px each row stacks, its first cell as the title and the rest under their column names.
- **Times:** `YYYY-MM-DD HH:MM UTC`; dates alone as `YYYY-MM-DD`.
- **Commands in messages:** text between backticks shows as code.
- **Errors:** a message on the red ground, in words that say what to do.
- **App window:** one status ring coloured by the verdict, the product label, ink buttons, and the device facts in mono. No glows or gradients.

## Do's and Don'ts

### Do:
- **Do** generate every capture, ladder and timeline from the product at build time, and fail the build when the expected output is missing.
- **Do** number figures and caption them with what they show.
- **Do** put "What it does not claim" on every product overview, as a list.
- **Do** give drawn figures a phone-width drawing rather than shrinking text below 12px.

### Don't:
- **Don't** use colour, the hatch or mono for anything but their one meaning.
- **Don't** use shadows, gradients as decoration, eyebrows above headings, or coloured side-borders.
- **Don't** show invented output, customers, testimonials, benchmarks or prices.
- **Don't** name another product on a product's pages.
