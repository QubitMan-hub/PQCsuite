"""Optional JavaScript/TypeScript syntax trees, normalized into the shared crawler graph."""
import posixpath
from pathlib import PurePosixPath

FUNCTIONS = {'function_declaration', 'generator_function_declaration', 'function_expression', 'generator_function', 'arrow_function', 'method_definition'}


def module(path):
    if path in {'', '.'}:
        return 'index'
    p = PurePosixPath(path)
    return str(p.with_suffix('') if p.suffix in {'.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx'} else p).replace('/', '.').removesuffix('.index')


def observe(crawler, path, text):
    language = 'TypeScript' if PurePosixPath(path).suffix in {'.ts', '.tsx'} else 'JavaScript'
    try:
        from tree_sitter import Language, Parser
        if language == 'TypeScript':
            import tree_sitter_typescript as grammar
            factory = grammar.language_tsx if path.endswith('.tsx') else grammar.language_typescript
        else:
            import tree_sitter_javascript as grammar
            factory = grammar.language
        key = language + (':tsx' if path.endswith('.tsx') else '')
        parser = crawler.parsers.get(key)
        if parser is None:
            parser = crawler.parsers[key] = Parser(Language(factory()))
    except ImportError:
        crawler.skipped[language] += 1
        return
    symbol_start, alias_start = len(crawler.symbols), len(crawler.aliases)
    source = text.encode('utf-8')
    tree = parser.parse(source)
    if tree.root_node.has_error:
        crawler.skipped[language + ' (syntax errors)'] += 1
        return
    crawler.languages[language] += 1
    crawler.files += 1
    mod = module(path)

    def field(node, name):
        return node.child_by_field_name(name)

    def arguments(node):
        args = field(node, 'arguments')
        return args.named_children if args and args.type == 'arguments' else []

    def spelling(node):
        return source[node.start_byte:node.end_byte].decode('utf-8') if node else ''

    def dotted(node):
        if node is None:
            return ''
        if node.type in {'identifier', 'property_identifier', 'type_identifier', 'shorthand_property_identifier'}:
            return spelling(node)
        if node.type == 'member_expression':
            base = dotted(field(node, 'object'))
            return base + '.' + dotted(field(node, 'property')) if base else ''
        return ''

    def function_name(node):
        name = dotted(field(node, 'name'))
        parent = node.parent
        if not name and parent and parent.type == 'variable_declarator':
            name = dotted(field(parent, 'name'))
        if not name and parent and parent.type == 'assignment_expression':
            left = dotted(field(parent, 'left'))
            if left == 'module.exports':
                name = 'default'
            elif left.startswith(('exports.', 'module.exports.')):
                name = left.rsplit('.', 1)[-1]
        return name

    def bindings(nodes, prefix, parameters=None):
        table = {}
        def bind(name, target):
            if name:
                table[name] = None if name in table else target
        def collect(node):
            if node.type in FUNCTIONS:
                name = function_name(node)
                bind(name, mod + '.' + '.'.join(x for x in (prefix, name) if x))
                return
            if node.type in {'class_declaration', 'class'}:
                bind(dotted(field(node, 'name')), None)
                return
            if node.type == 'import_statement':
                dep = spelling(field(node, 'source'))[1:-1]
                base = module(posixpath.normpath(posixpath.join(posixpath.dirname(path), dep))) if dep.startswith('.') else dep
                def imports(n):
                    if n.type == 'import_specifier':
                        bind(dotted(field(n, 'alias')) or dotted(field(n, 'name')), base + '.' + dotted(field(n, 'name')))
                    elif n.type == 'namespace_import':
                        bind(dotted(n.named_children[-1]), base)
                    elif n.type == 'identifier' and n.parent.type == 'import_clause':
                        bind(dotted(n), base + '.default')
                    else:
                        for c in n.named_children:
                            imports(c)
                imports(node)
                return
            if node.type == 'variable_declarator':
                value = field(node, 'value')
                name = dotted(field(node, 'name'))
                if value and value.type in FUNCTIONS:
                    bind(name, mod + '.' + '.'.join(x for x in (prefix, name) if x))
                    return
                if value and value.type == 'call_expression' and dotted(field(value, 'function')) == 'require':
                    args = arguments(value)
                    if len(args) == 1 and args[0].type == 'string':
                        dep = spelling(args[0])[1:-1]
                        base = module(posixpath.normpath(posixpath.join(posixpath.dirname(path), dep))) if dep.startswith('.') else dep
                        bind(name, base + '.*')
                        pattern = field(node, 'name')
                        if pattern.type == 'object_pattern':
                            for item in pattern.named_children:
                                if item.type == 'shorthand_property_identifier_pattern':
                                    bind(spelling(item), base + '.' + spelling(item))
                                elif item.type == 'pair_pattern':
                                    bind(dotted(field(item, 'value')), base + '.' + dotted(field(item, 'key')))
                        return
                bind(name, None)
            if node.type in {'assignment_expression', 'augmented_assignment_expression', 'update_expression'}:
                bind(dotted(field(node, 'left') or field(node, 'argument')), None)
            for c in node.named_children:
                collect(c)
        if parameters:
            # Parameter identifiers/patterns shadow outer bindings; defaults are not resolved as body calls.
            def params(n):
                if n.type == 'identifier':
                    bind(spelling(n), None)
                else:
                    for c in n.named_children:
                        params(c)
            params(parameters)
        for n in nodes:
            collect(n)
        return table

    stack = [('', bindings(tree.root_node.named_children, ''), 'module')]
    crawler.add_symbol(path, mod, '', 'module', 1, text.count('\n') + 1, language=language)

    def exported_name(node):
        if node.type != 'assignment_expression':
            return ''
        left = dotted(field(node, 'left'))
        if left.split('.')[0] in stack[0][1]:
            return ''
        if left == 'module.exports':
            return 'default'
        return left.rsplit('.', 1)[-1] if left.startswith(('exports.', 'module.exports.')) else ''

    def visit(node):
        if node.type in FUNCTIONS or node.type in {'class_declaration', 'class'}:
            name = function_name(node) if node.type in FUNCTIONS else dotted(field(node, 'name'))
            if not name:
                crawler.uncertain_lines[path].update(range(node.start_point.row + 1, node.end_point.row + 2))
                return  # anonymous callbacks are not assigned to an enclosing workflow
            qual = '.'.join(x for x in (stack[-1][0], name) if x)
            body = field(node, 'body')
            kind = 'function' if node.type in FUNCTIONS else 'class'
            parent = node.parent
            ancestors = []
            while parent and parent.type in {'variable_declarator', 'lexical_declaration', 'variable_declaration', 'export_statement', 'assignment_expression', 'expression_statement'}:
                ancestors.append(parent)
                parent = parent.parent
            exported = not stack[-1][0] and any(n.type == 'export_statement' or exported_name(n) for n in ancestors)
            default = any(n.type == 'export_statement' and any(c.type == 'default' for c in n.children) for n in ancestors)
            crawler.add_symbol(path, mod, qual, kind, node.start_point.row + 1, node.end_point.row + 1,
                               language=language, body_line=body.start_point.row + 1 if body else node.end_point.row + 1,
                               exported=exported, aliases=['default'] if default else [])
            parameters = field(node, 'parameters') or field(node, 'parameter')
            def defaults(n):
                if n.type == 'call_expression':
                    crawler.uncertain_lines[path].update(range(n.start_point.row + 1, n.end_point.row + 2))
                for c in n.named_children:
                    defaults(c)
            if parameters:
                defaults(parameters)
            if body:
                children = body.named_children if body.type in {'statement_block', 'class_body'} else [body]
                stack.append((qual, bindings(children, qual, field(node, 'parameters') or field(node, 'parameter')), kind))
                for c in children:
                    visit(c)
                stack.pop()
            return
        if node.type == 'assignment_expression' and not stack[-1][0]:
            left, right = dotted(field(node, 'left')), field(node, 'right')
            alias = exported_name(node)
            if alias:
                def export(alias, value):
                    if value is None:
                        return
                    target = stack[0][1].get(dotted(value))
                    if value.type == 'call_expression' and dotted(field(value, 'function')) == 'require':
                        args = arguments(value)
                        if len(args) == 1 and args[0].type == 'string':
                            dep = spelling(args[0])[1:-1]
                            base = module(posixpath.normpath(posixpath.join(posixpath.dirname(path), dep))) if dep.startswith('.') else dep
                            target = base + '.default'
                    if target and target.endswith('.*'):
                        target = target[:-2] + '.default'
                    if target:
                        crawler.add_alias('web', mod + '.' + alias, target)
                if left == 'module.exports' and right and right.type == 'object':
                    for item in right.named_children:
                        if item.type == 'pair':
                            export(dotted(field(item, 'key')), field(item, 'value'))
                        elif item.type == 'shorthand_property_identifier':
                            export(spelling(item), item)
                elif right and right.type not in FUNCTIONS:
                    export(alias, right)
        if node.type == 'import_statement':
            crawler.add_import(path, stack[-1][0], spelling(field(node, 'source'))[1:-1], node.start_point.row + 1)
        if node.type in {'call_expression', 'new_expression'}:
            name = dotted(field(node, 'function') or field(node, 'constructor'))
            head, _, tail = name.partition('.')
            candidate = ''
            for _, table, kind in reversed(stack):
                if kind == 'class' and stack[-1][2] == 'function':
                    continue
                if head in table:
                    bound = table[head]
                    candidate = (bound[:-2] + ('.' + tail if tail else '.default') if bound.endswith('.*') else bound + ('.' + tail if tail else '')) if bound else ''
                    break
            if name == 'require':
                args = arguments(node)
                if len(args) == 1 and args[0].type == 'string':
                    crawler.add_import(path, stack[-1][0], spelling(args[0])[1:-1], node.start_point.row + 1)
            crawler.add_call(path, stack[-1][0], node.start_point.row + 1, name or 'dynamic call', candidate)
        for c in node.named_children:
            visit(c)
    visit(tree.root_node)
    targets = {a['target'] for a in crawler.aliases[alias_start:]}
    for symbol in crawler.symbols[symbol_start:]:
        if symbol['module'] + '.' + symbol['name'] in targets:
            symbol['exported'] = True
