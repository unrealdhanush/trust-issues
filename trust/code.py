"""Small AST helpers: where functions are, and what a module defines and uses."""

import ast


def parse(src):
    try:
        return ast.parse(src)
    except SyntaxError:
        return None


def function_spans(src):
    """{qualname: (first line incl. decorators, last line)} for every def and class."""
    tree = parse(src)
    spans = {}
    if tree is None:
        return spans

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                start = min([d.lineno for d in child.decorator_list] + [child.lineno])
                spans[name] = (start, child.end_lineno)
                visit(child, name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return spans


def enclosing_function(src, line):
    """The innermost def or class containing `line`, or "<module>"."""
    hits = [(s, name) for name, (s, e) in function_spans(src).items() if s <= line <= e]
    return max(hits)[1] if hits else "<module>"


def definitions(src):
    """{qualname: ast.dump of the node} for every def and class, positions excluded."""
    tree = parse(src)
    out = {}
    if tree is None:
        return out

    def visit(node, prefix):
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                name = prefix + child.name
                out[name] = (ast.dump(child), bool(child.decorator_list))
                visit(child, name + ".")
            else:
                visit(child, prefix)

    visit(tree, "")
    return out


def used_names(tree):
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
    return names


def module_bindings(tree):
    """Top-level names bound by imports and assignments: {name: kind}."""
    out = {}
    for node in tree.body:
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for alias in node.names:
                out[(alias.asname or alias.name).split(".")[0]] = "import"
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for t in targets:
                for n in ast.walk(t):
                    if isinstance(n, ast.Name):
                        out[n.id] = "assignment"
    return out


def imported_modules(tree):
    mods = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            mods.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            mods.add("." * node.level + (node.module or "").split(".")[0])
    return mods
