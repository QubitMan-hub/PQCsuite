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
        crawler.gap(language, path)
        return
    symbol_start, alias_start = len(crawler.symbols), len(crawler.aliases)
    source = text.encode('utf-8')
    tree = crawler.parse(key, source, parser.parse)
    if tree.root_node.has_error:
        crawler.gap(language + ' (syntax errors)', path)
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
                        crawler.add_alias('web', mod + '.' + alias, target, path)
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
    hints = crypto_aliases(tree, source)
    crawler.crypto_contexts.extend(hybrid_contexts(tree, source, path))
    return hints


def crypto_aliases(tree, source):
    """Resolve immutable, locally consumed signer tables; ambiguous/mutated tables stay unknown."""
    from .scouts.names import algos
    def text(node):
        return source[node.start_byte:node.end_byte].decode('utf-8') if node else ''
    def field(node, name):
        return node.child_by_field_name(name)
    def walk(node):
        yield node
        for child in node.named_children:
            yield from walk(child)
    imported = {}
    for statement in tree.root_node.named_children:
        if statement.type == 'import_statement':
            for node in walk(statement):
                if node.type == 'import_specifier':
                    name = text(field(node, 'name'))
                    imported[text(field(node, 'alias')) or name] = algos(name)
    rebound = set()
    for node in walk(tree.root_node):
        targets = []
        if node.type == 'variable_declarator':
            targets = [field(node, 'name')]
        elif node.type in {'assignment_expression', 'augmented_assignment_expression', 'update_expression'}:
            targets = [field(node, 'left') or field(node, 'argument')]
        elif node.type in FUNCTIONS:
            targets = [field(node, 'parameters') or field(node, 'parameter')]
        for target in targets:
            if target:
                rebound.update(text(n) for n in walk(target) if n.type == 'identifier')
    imported = {name: found for name, found in imported.items() if name not in rebound}
    hints = []
    for loop in walk(tree.root_node):
        if loop.type != 'for_in_statement' or text(field(loop, 'kind')) != 'const' or text(field(loop, 'operator')) != 'of':
            continue
        left, right, body = (field(loop, key) for key in ('left', 'right', 'body'))
        if not left or left.type != 'array_pattern' or left.children[1].type != 'identifier' or not right or right.type != 'identifier':
            continue
        alias, table = text(left.children[1]), text(right)
        block = loop.parent
        if block.type not in {'program', 'statement_block'}:
            continue
        uses = [n for n in walk(block) if n.type == 'identifier' and text(n) == table]
        if len(uses) != 2:
            continue  # Other references may mutate or escape the table.
        declarations = [n for n in block.named_children if n.type == 'lexical_declaration' and text(field(n, 'kind')) == 'const' and n.end_byte < loop.start_byte]
        values = [field(n, 'value') for d in declarations for n in d.named_children if n.type == 'variable_declarator' and text(field(n, 'name')) == table]
        if len(values) != 1:
            continue
        value = values[0]
        if value and value.type == 'as_expression':
            value = value.named_children[0]
        if not value or value.type != 'array' or not value.named_children:
            continue
        families = set()
        for row in value.named_children:
            if row.type != 'array' or len(row.children) < 3 or row.children[1].type != 'identifier':
                break
            found = imported.get(text(row.children[1]), [])
            if len(found) != 1 or not found[0].startswith('ML-DSA-'):
                break
            families.add(found[0])
        else:
            references = [n for n in walk(body) if n.type == 'identifier' and text(n) == alias]
            if not references or any(n.parent.type != 'member_expression' or field(n.parent, 'object') != n or
                                     n.parent.parent.type != 'call_expression' or field(n.parent.parent, 'function') != n.parent for n in references):
                continue
            # Nested callbacks can capture a reassigned binding; do not infer their scope.
            if any(n.type in FUNCTIONS or n.type == 'for_in_statement' for n in walk(body)):
                continue
            hints.append((body.start_point.row + 1, body.end_point.row + 1, alias, sorted(families)))
    return hints


def hybrid_contexts(tree, source, path):
    """Paired arguments are composition evidence, never proof of a secure combiner."""
    from .scouts.names import algos
    contexts = []
    def spelling(node):
        return source[node.start_byte:node.end_byte].decode('utf-8') if node else ''
    def walk(node):
        if node.type == 'call_expression':
            args = node.child_by_field_name('arguments')
            if args:
                pq = [spelling(a) for a in args.named_children if a.type == 'identifier' and any(x.startswith('ML-KEM-') for x in algos(spelling(a))) ]
                for arg in args.named_children if pq else []:
                    if arg.type == 'call_expression':
                        callee = spelling(arg.child_by_field_name('function'))
                        classical = set(algos(callee)) & {'ECDH', 'X25519', 'X448', 'RSA', 'DH'}
                        if classical:
                            contexts.append({'file': path, 'line': arg.start_point.row + 1, 'end_line': arg.end_point.row + 1,
                                             'algorithms': sorted(classical), 'pqc_arguments': pq,
                                             'combiner': spelling(node.child_by_field_name('function')),
                                             'basis': 'Classical constructor and named PQC value passed to the same call; combiner security and deployed use unverified'})
        for child in node.named_children:
            walk(child)
    walk(tree.root_node)
    return contexts
