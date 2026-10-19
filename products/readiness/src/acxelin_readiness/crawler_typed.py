"""Optional Java and Go syntax trees, normalized into the shared crawler graph.

Both languages declare types, so a call is resolved from what the source states: the enclosing class or package, an
import, a field, parameter, local variable or Go receiver of a declared type. A call through anything else (an
interface value, a lambda, reflection, a variable whose type is inferred) stays unresolved rather than guessed."""
from pathlib import PurePosixPath

GRAMMARS = {"Java": "tree_sitter_java", "Go": "tree_sitter_go"}


def parser(crawler, language):
    if language not in crawler.parsers:
        from importlib import import_module
        from tree_sitter import Language, Parser
        crawler.parsers[language] = Parser(Language(import_module(GRAMMARS[language]).language()))
    return crawler.parsers[language]


def observe(crawler, path, text, language):
    try:
        p = parser(crawler, language)
    except ImportError:
        crawler.gap(language, path)
        return
    source = text.encode("utf-8")
    tree = crawler.parse(language, source, p.parse)
    if tree.root_node.has_error:
        crawler.gap(language + " (syntax errors)", path)
        return
    crawler.languages[language] += 1
    crawler.files += 1
    (java if language == "Java" else go)(crawler, path, source, tree, text.count("\n") + 1)


def spelling(source, node):
    return source[node.start_byte:node.end_byte].decode("utf-8") if node else ""


def walk(node):
    yield node
    for child in node.named_children:
        yield from walk(child)


def java(crawler, path, source, tree, lines):
    text = lambda n: spelling(source, n)
    root = tree.root_node
    package = next((text(n.named_children[0]) for n in root.named_children if n.type == "package_declaration"), "")
    imports = {}
    for n in root.named_children:
        if n.type == "import_declaration":
            name = text(n.named_children[0])
            crawler.add_import(path, "", name, n.start_point.row + 1)
            if not any(c.type == "asterisk" for c in n.children):
                imports[name.rsplit(".", 1)[-1]] = name
    qualify = lambda t: imports.get(t) or f"{package}.{t}"
    crawler.add_symbol(path, package, "", "module", 1, lines, language="Java")

    def type_of(node):
        t = node.child_by_field_name("type") if node else None
        while t is not None and t.type in ("generic_type", "array_type", "scoped_type_identifier") and t.named_children:
            if t.type == "scoped_type_identifier":
                return text(t)
            t = t.named_children[0]
        return text(t) if t is not None and t.type == "type_identifier" else ""

    def typed(nodes):
        """Names declared with a class type: fields, parameters and local variables."""
        out = {}
        for n in nodes:
            if n.type in ("field_declaration", "local_variable_declaration", "formal_parameter"):
                t = type_of(n)
                names = [n.child_by_field_name("name")] if n.type == "formal_parameter" else \
                    [d.child_by_field_name("name") for d in n.named_children if d.type == "variable_declarator"]
                for name in names:
                    key = text(name)
                    out[key] = None if key in out or not t else qualify(t)
        return out

    def visit_class(node, outer):
        name = text(node.child_by_field_name("name"))
        qual = ".".join(x for x in (outer, name) if x)
        crawler.add_symbol(path, package, qual, "class", node.start_point.row + 1, node.end_point.row + 1, language="Java")
        body = node.child_by_field_name("body")
        fields = typed(body.named_children) if body else {}
        for member in body.named_children if body else []:
            if member.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
                visit_class(member, qual)
            elif member.type in ("method_declaration", "constructor_declaration"):
                method = name if member.type == "constructor_declaration" else text(member.child_by_field_name("name"))
                block = member.child_by_field_name("body")
                crawler.add_symbol(path, package, f"{qual}.{method}", "function", member.start_point.row + 1, member.end_point.row + 1,
                                   language="Java", body_line=block.start_point.row + 1 if block else member.end_point.row + 1)
                if block:
                    params = member.child_by_field_name("parameters")
                    scope = fields | typed(params.named_children if params else []) | typed(walk(block))
                    calls(block, qual, f"{qual}.{method}", scope)

    def calls(block, cls, source_name, scope):
        for n in walk(block):
            if n.type in ("lambda_expression", "class_body") and n is not block:
                crawler.uncertain_lines[path].update(range(n.start_point.row + 1, n.end_point.row + 2))
            if n.type == "method_invocation":
                obj, name = n.child_by_field_name("object"), text(n.child_by_field_name("name"))
                if obj is None or obj.type == "this":
                    target = f"{package}.{cls}.{name}"
                elif obj.type == "identifier" and scope.get(text(obj)):
                    target = f"{scope[text(obj)]}.{name}"
                elif obj.type == "identifier" and text(obj) not in scope and text(obj)[:1].isupper():
                    target = f"{qualify(text(obj))}.{name}"
                else:
                    target = ""
                label = (f"{text(obj)}.{name}" if obj is not None else name)[:120]
                crawler.add_call(path, source_name, n.start_point.row + 1, label, target)
            elif n.type == "object_creation_expression":
                t = type_of(n)
                crawler.add_call(path, source_name, n.start_point.row + 1, "new " + (t or "?"), qualify(t) if t else "")

    for n in root.named_children:
        if n.type in ("class_declaration", "interface_declaration", "enum_declaration", "record_declaration"):
            visit_class(n, "")


def go(crawler, path, source, tree, lines):
    text = lambda n: spelling(source, n)
    root = tree.root_node
    folder = str(PurePosixPath(path).parent)
    module = "" if folder == "." else folder
    imports = {}
    for decl in root.named_children:
        if decl.type == "import_declaration":
            for spec in walk(decl):
                if spec.type == "import_spec":
                    target = text(spec.child_by_field_name("path")).strip('"`')
                    alias = text(spec.child_by_field_name("name")) or target.rsplit("/", 1)[-1]
                    crawler.add_import(path, "", target, spec.start_point.row + 1)
                    if alias not in ("_", "."):
                        imports[alias] = target
    crawler.add_symbol(path, module, "", "module", 1, lines, language="Go")
    local = lambda name: f"{module}.{name}"

    def type_name(node):
        while node is not None and node.type in ("pointer_type", "generic_type") and node.named_children:
            node = node.named_children[0]
        return text(node) if node is not None and node.type == "type_identifier" else ""

    for decl in root.named_children:
        if decl.type not in ("function_declaration", "method_declaration"):
            continue
        name, body = text(decl.child_by_field_name("name")), decl.child_by_field_name("body")
        scope = {}
        receiver = decl.child_by_field_name("receiver")
        owner = ""
        for group in [receiver, decl.child_by_field_name("parameters")]:
            for p in group.named_children if group is not None else []:
                if p.type == "parameter_declaration":
                    t = type_name(p.child_by_field_name("type"))
                    for ident in p.named_children:
                        if ident.type == "identifier":
                            scope[text(ident)] = t or None
                            if group is receiver:
                                owner = t
        qual = f"{owner}.{name}" if owner else name
        crawler.add_symbol(path, module, qual, "function", decl.start_point.row + 1, decl.end_point.row + 1, language="Go",
                           body_line=body.start_point.row + 1 if body else decl.end_point.row + 1)
        for n in walk(body) if body is not None else []:
            if n.type == "var_spec":
                t = type_name(n.child_by_field_name("type"))
                for ident in n.named_children:
                    if ident.type == "identifier":
                        scope[text(ident)] = t or None
            elif n.type in ("short_var_declaration", "assignment_statement"):
                for ident in walk(n.child_by_field_name("left")):
                    if ident.type == "identifier":
                        scope[text(ident)] = None
            elif n.type == "func_literal":
                crawler.uncertain_lines[path].update(range(n.start_point.row + 1, n.end_point.row + 2))
            elif n.type == "call_expression":
                fn = n.child_by_field_name("function")
                target = ""
                if fn.type == "identifier" and text(fn) not in scope:
                    target = local(text(fn))
                elif fn.type == "selector_expression":
                    operand, field = fn.child_by_field_name("operand"), text(fn.child_by_field_name("field"))
                    head = text(operand) if operand.type == "identifier" else ""
                    if head in scope:
                        target = local(f"{scope[head]}.{field}") if scope[head] else ""
                    elif head in imports:
                        target = f"{imports[head]}.{field}"
                crawler.add_call(path, qual, n.start_point.row + 1, text(fn)[:120], target)
