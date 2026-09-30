"""Bounded Python AST relationships. Never executes code or retains source/argument values."""
import ast
import json
from collections import defaultdict, deque


LIMIT_SYMBOLS = 20_000
LIMIT_CALLS = 100_000


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return base + "." + node.attr if base else ""
    return ""


class CodeCrawler:
    def __init__(self):
        self.symbols = []
        self.calls = []
        self.imports = []
        self.files = 0
        self.limited = False
        self.uncertain_lines = defaultdict(set)

    def observe(self, path, tree):
        """Called with the very AST the existing cryptographic detector uses."""
        self.files += 1
        module = path.removesuffix(".py").replace("/", ".").removesuffix(".__init__")
        if module == "__init__":
            module = ""
        package = module if path.endswith("/__init__.py") else module.rpartition(".")[0]
        crawler = self
        # Bindings collected per lexical scope. Reassignment/shadowing is uncertain.
        def bindings(body, params=()):
            table = defaultdict(list)
            for param in params:
                table[param].append(None)
            class Bind(ast.NodeVisitor):
                def visit_Import(self, n):
                    for a in n.names:
                        table[a.asname or a.name.split(".")[0]].append(a.name if a.asname else a.name.split(".")[0])
                def visit_ImportFrom(self, n):
                    base = n.module or ""
                    if n.level:
                        parts = package.split(".") if package else []
                        base = ".".join(parts[:len(parts) - n.level + 1] + ([base] if base else [])) if n.level <= len(parts) else ""
                    for a in n.names:
                        if a.name != "*":
                            table[a.asname or a.name].append(base + "." + a.name if base else None)
                def visit_Name(self, n):
                    if isinstance(n.ctx, (ast.Store, ast.Del)):
                        table[n.id].append(None)
                def visit_FunctionDef(self, n):
                    table[n.name].append("@" + n.name)
                visit_AsyncFunctionDef = visit_FunctionDef
                def visit_ClassDef(self, n):
                    table[n.name].append("@" + n.name)
                def visit_Lambda(self, n):
                    pass
            visitor = Bind()
            for node in body:
                visitor.visit(node)
            return {name: values[0] if len(values) == 1 else None for name, values in table.items()}

        class Visitor(ast.NodeVisitor):
            def __init__(self):
                self.stack = [("", bindings(tree.body), "module")]
                self.add("", "module", tree)
            def add(self, qual, kind, node, **extra):
                if len(crawler.symbols) >= LIMIT_SYMBOLS:
                    crawler.limited = True
                    return
                crawler.symbols.append({"id": path + "#" + qual, "file": path, "module": module, "name": qual or module,
                                        "kind": kind, "line": getattr(node, "lineno", 1), "end_line": getattr(node, "end_lineno", 10**9), **extra})
            def visit_FunctionDef(self, node):
                qual = ".".join(x for x in (self.stack[-1][0], node.name) if x)
                self.add(qual, "function", node, body_line=node.body[0].lineno if node.body else node.lineno)
                # Decorators/defaults execute in the defining scope, not the function.
                for n in node.decorator_list + node.args.defaults + [n for n in node.args.kw_defaults if n is not None]:
                    self.visit(n)
                params = [a.arg for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs]
                params += [a.arg for a in (node.args.vararg, node.args.kwarg) if a]
                self.stack.append((qual, bindings(node.body, params), "function"))
                for n in node.body:
                    self.visit(n)
                self.stack.pop()
            visit_AsyncFunctionDef = visit_FunctionDef
            def visit_ClassDef(self, node):
                qual = ".".join(x for x in (self.stack[-1][0], node.name) if x)
                self.add(qual, "class", node, bases=[dotted(n) for n in node.bases if dotted(n)])
                for n in node.bases + node.decorator_list:
                    self.visit(n)
                self.stack.append((qual, bindings(node.body), "class"))
                for n in node.body:
                    self.visit(n)
                self.stack.pop()
            def visit_Lambda(self, node):
                # Anonymous functions have uncertain invocation; do not attribute their calls to the enclosing workflow.
                crawler.uncertain_lines[path].update(range(node.lineno, node.end_lineno + 1))
            def visit_Import(self, node):
                for a in node.names:
                    self.record_import(node, a.name)
            def visit_ImportFrom(self, node):
                self.record_import(node, "." * node.level + (node.module or ""))
            def record_import(self, node, name):
                if len(crawler.imports) >= LIMIT_CALLS:
                    crawler.limited = True
                    return
                crawler.imports.append({"file": path, "source": path + "#" + self.stack[-1][0], "module": name, "line": node.lineno})
            def visit_Call(self, node):
                if len(crawler.calls) >= LIMIT_CALLS:
                    crawler.limited = True
                    return
                name, candidate = dotted(node.func), ""
                if name:
                    head, _, tail = name.partition(".")
                    for qual, names, kind in reversed(self.stack):
                        if kind == "class" and self.stack[-1][2] == "function":
                            continue  # class attributes are not lexical names in methods
                        if head in names:
                            bound = names[head]
                            if bound and bound.startswith("@"):
                                candidate = module + "." + ".".join(x for x in (qual, bound[1:], tail) if x)
                            elif bound:
                                candidate = bound + ("." + tail if tail else "")
                            break
                crawler.calls.append({"source": path + "#" + self.stack[-1][0], "file": path, "line": node.lineno,
                                      "callee": name or "dynamic call", "candidate": candidate})
                self.generic_visit(node)
        Visitor().visit(tree)

    def finish(self, assets):
        names = defaultdict(list)
        for symbol in self.symbols:
            canonical = symbol["module"] + ("." + symbol["name"] if symbol["kind"] != "module" else "")
            names[canonical].append(symbol["id"])
            if canonical.startswith("src."):
                names[canonical[4:]].append(symbol["id"])
        callers = defaultdict(set)
        calls = []
        for raw in self.calls:
            call = {k: v for k, v in raw.items() if k != "candidate"}
            matches = names.get(raw["candidate"], [])
            call["reference"] = raw["candidate"] or None
            call["target"] = matches[0] if len(matches) == 1 else None
            call["confidence"] = "observed static reference" if call["target"] else "unresolved; inspect dispatch"
            if call["target"]:
                callers[call["target"]].add(call["source"])
            calls.append(call)
        by_file = defaultdict(list)
        for symbol in self.symbols:
            if symbol["kind"] == "function":
                by_file[symbol["file"]].append(symbol)
        for asset in assets:
            owners = set()
            for sighting in asset.sightings:
                if sighting.evidence == "import" or sighting.verdict != "accepted":
                    continue
                enclosing = [s for s in by_file[sighting.file] if s.get("body_line", s["line"]) <= sighting.line <= s["end_line"] and sighting.line not in self.uncertain_lines[sighting.file]]
                if enclosing:
                    owners.add(min(enclosing, key=lambda s: s["end_line"] - s["line"])["id"])
            affected, pending = set(owners), deque(sorted(owners))
            while pending and len(affected) < 500:
                for caller in sorted(callers[pending.popleft()]):
                    if caller not in affected:
                        affected.add(caller)
                        pending.append(caller)
                        if len(affected) >= 500:
                            break
            if owners:
                asset.params["code_impact"] = {"functions": sorted(owners), "callers": sorted(affected - owners),
                                             "limited": bool(pending), "basis": "static references; runtime reachability and business ownership are not established"}
        return {"version": 1, "language": "Python", "files_analyzed": self.files, "symbols": self.symbols,
                "calls": calls, "imports": self.imports, "limited": self.limited,
                "limitations": ["Python AST only; other languages keep their existing crypto detectors.",
                                "Dynamic dispatch, wildcard imports, callbacks and runtime reassignment require manual review.",
                                "No source snippets, argument values, docstrings or runtime execution are included."]}


def impact_property(asset):
    value = asset.params.get("code_impact")
    return json.dumps(value, separators=(",", ":")) if value else None
