"""Remove every comment and docstring from the code this repository republishes.

The source under app/ and tests/ is copied from a private application whose comments explain
operational history. The code is the part worth showing, so the comments are removed rather than
edited one by one: a re-sync brings new comments with it, and a reviewer cannot prove that a
hand-edited comment set is clean.

    python demo/strip_comments.py            # strip in place, and report what was removed
    python demo/strip_comments.py --check    # verify only, non-zero if anything is left

Scope
    app/**/*.py, tests/**/*.py    comments and docstrings (tokenize + ast)
    app/static/index.html         JS comments in <script>, CSS comments in <style>, HTML comments
    tests/*.js                    JS comments
    demo/*.py                     comments only; the demo's own docstrings are its documentation

Every rewrite is verified before it is written. Python: the AST of the result must equal the AST of
the original with its docstrings removed. JS: the sequence of tokens, and whether a line break
precedes each one (which is what automatic semicolon insertion reads), must be identical. CSS and
HTML: re-scanning the result must find no comment. A file that fails verification is left untouched
and the run exits non-zero. The tool is idempotent: a second run changes nothing.
"""
from __future__ import annotations

import argparse
import ast
import io
import pathlib
import re
import sys
import tokenize

ROOT = pathlib.Path(__file__).resolve().parents[1]

JS_WS = " \t\r\n\f\v ﻿  "
JS_NL = "\r\n  "
REGEX_KEYWORDS = {
    "return", "typeof", "instanceof", "in", "of", "new", "delete", "void", "throw", "case",
    "do", "else", "yield", "await", "extends",
}


class StripError(Exception):
    pass


def _line_bounds(text: str, start: int, end: int) -> tuple[int, int]:
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    if line_end < 0:
        line_end = len(text)
    return line_start, line_end


def _prev_line(text: str, line_start: int) -> str | None:
    if line_start == 0:
        return None
    prev_start = text.rfind("\n", 0, line_start - 1) + 1
    return text[prev_start:line_start - 1]


def remove_spans(text: str, spans: list[tuple[int, int, str]], opener: str) -> str:
    for start, end, repl in sorted(spans, reverse=True):
        line_start, line_end = _line_bounds(text, start, end)
        before = text[line_start:start]
        after = text[end:line_end]
        body = text[start:end]
        if repl:
            text = text[:start] + repl + text[end:]
            continue
        if not before.strip() and not after.strip():
            cut_end = min(line_end + 1, len(text))
            prev = _prev_line(text, line_start)
            nxt_end = text.find("\n", cut_end)
            nxt = text[cut_end:nxt_end if nxt_end >= 0 else len(text)]
            prev_blank = prev is None or not prev.strip() or prev.rstrip().endswith(opener)
            if prev_blank and cut_end < len(text) and not nxt.strip() and nxt_end >= 0:
                cut_end = nxt_end + 1
            text = text[:line_start] + text[cut_end:]
        elif not before.strip():
            stop = end
            while stop < len(text) and text[stop] in " \t":
                stop += 1
            text = text[:start] + text[stop:]
        elif not after.strip():
            begin = start
            while begin > line_start and text[begin - 1] in " \t":
                begin -= 1
            text = text[:begin] + text[line_end:]
        elif any(ch in body for ch in JS_NL):
            text = text[:start] + "\n" + text[end:]
        else:
            left = text[start - 1] if start else ""
            right = text[end] if end < len(text) else ""
            if left in " \t" and right in " \t":
                text = text[:start] + text[end + 1:]
            elif left in " \t" or right in " \t":
                text = text[:start] + text[end:]
            else:
                text = text[:start] + " " + text[end:]
    return text


class _DropDocstrings(ast.NodeTransformer):
    def _fix(self, node):
        self.generic_visit(node)
        for field in ("body", "orelse", "finalbody"):
            body = getattr(node, field, None)
            if not isinstance(body, list) or not body or not isinstance(body[0], ast.stmt):
                continue
            kept = [s for s in body if not _is_str_stmt(s)]
            if len(kept) != len(body):
                setattr(node, field, kept or [ast.Pass()])
        return node

    visit_Module = visit_ClassDef = visit_FunctionDef = visit_AsyncFunctionDef = _fix
    visit_If = visit_For = visit_AsyncFor = visit_While = visit_With = visit_AsyncWith = _fix
    visit_Try = visit_ExceptHandler = _fix
    if hasattr(ast, "TryStar"):
        visit_TryStar = _fix
    if hasattr(ast, "match_case"):
        visit_match_case = _fix


def _is_str_stmt(s) -> bool:
    return (isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant)
            and isinstance(s.value.value, str))


def _norm_ast(tree) -> str:
    return ast.dump(tree, annotate_fields=True, include_attributes=False)


def _lines(text: str) -> list[str]:
    parts = text.split("\n")
    lines = [p + "\n" for p in parts[:-1]]
    return lines + [parts[-1]] if parts[-1] else lines


def _offsets(text: str) -> list[int]:
    starts, pos = [0], 0
    for line in _lines(text):
        pos += len(line)
        starts.append(pos)
    return starts


def python_spans(text: str, docstrings: bool) -> list[tuple[int, int, str]]:
    starts = _offsets(text)
    lines = _lines(text)

    def char_off(lineno: int, byte_col: int) -> int:
        line = lines[lineno - 1] if lineno - 1 < len(lines) else ""
        col = len(line.encode("utf-8")[:byte_col].decode("utf-8"))
        return starts[lineno - 1] + col

    spans = []
    for tok in tokenize.generate_tokens(io.StringIO(text).readline):
        if tok.type != tokenize.COMMENT:
            continue
        if tok.start == (1, 0) and tok.string.startswith("#!"):
            continue
        spans.append((starts[tok.start[0] - 1] + tok.start[1],
                      starts[tok.end[0] - 1] + tok.end[1], ""))
    if not docstrings:
        return spans
    tree = ast.parse(text)
    for node in ast.walk(tree):
        for field in ("body", "orelse", "finalbody"):
            body = getattr(node, field, None)
            if not isinstance(body, list) or not body or not isinstance(body[0], ast.stmt):
                continue
            strs = [s for s in body if _is_str_stmt(s)]
            sole = len(strs) == len(body)
            for k, s in enumerate(strs):
                a = char_off(s.lineno, s.col_offset)
                b = char_off(s.end_lineno, s.end_col_offset)
                spans.append((a, b, "pass" if sole and k == 0 else ""))
    return spans


def strip_python(text: str, docstrings: bool) -> tuple[str, int]:
    spans = python_spans(text, docstrings)
    if not spans:
        return text, 0
    out = remove_spans(text, spans, ":").lstrip("\n")
    if text.startswith("#!") and not out.startswith("#!"):
        raise StripError("shebang lost")
    if out and not out.endswith("\n"):
        out += "\n"
    try:
        new_tree = ast.parse(out)
    except SyntaxError as e:
        raise StripError(f"result does not parse: {e}") from e
    old_tree = ast.parse(text)
    if docstrings:
        old_tree = _DropDocstrings().visit(old_tree)
    if _norm_ast(old_tree) != _norm_ast(new_tree):
        raise StripError("AST changed")
    if python_spans(out, docstrings):
        raise StripError("comments remain after stripping")
    return out, len(spans)


def _regex_allowed(last) -> bool:
    if last is None:
        return True
    kind, val = last
    if kind == "id":
        return val in REGEX_KEYWORDS
    if kind in ("num", "str", "tpl", "re"):
        return False
    return val not in (")", "]")


def js_lex(src: str):
    spans, toks = [], []
    i, n, stack, last, nl = 0, len(src), [], None, False

    def push(kind, a, b, val=None):
        nonlocal last, nl
        toks.append((src[a:b], nl and bool(toks)))
        last = (kind, val if val is not None else src[a:b])
        nl = False

    def scan_template(j):
        while j < n:
            ch = src[j]
            if ch == "\\":
                j += 2
                continue
            if ch == "`":
                return j + 1, True
            if ch == "$" and j + 1 < n and src[j + 1] == "{":
                stack.append("tpl")
                return j + 2, False
            j += 1
        raise StripError("unterminated template literal")

    while i < n:
        c = src[i]
        if c in JS_WS:
            if c in JS_NL:
                nl = True
            i += 1
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "/":
            j = i
            while j < n and src[j] not in JS_NL:
                j += 1
            spans.append((i, j, ""))
            i = j
            continue
        if c == "/" and i + 1 < n and src[i + 1] == "*":
            j = src.find("*/", i + 2)
            if j < 0:
                raise StripError("unterminated block comment")
            if any(ch in src[i:j] for ch in JS_NL):
                nl = True
            spans.append((i, j + 2, ""))
            i = j + 2
            continue
        if c == "/" and _regex_allowed(last):
            j, in_class = i + 1, False
            while True:
                if j >= n or src[j] in JS_NL:
                    raise StripError(f"unterminated regex at offset {i}")
                ch = src[j]
                if ch == "\\":
                    j += 2
                    continue
                if in_class:
                    in_class = ch != "]"
                elif ch == "[":
                    in_class = True
                elif ch == "/":
                    break
                j += 1
            j += 1
            while j < n and (src[j].isalnum() or src[j] in "_$"):
                j += 1
            push("re", i, j)
            i = j
            continue
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                if src[j] == "\\":
                    j += 1
                elif src[j] in "\r\n":
                    raise StripError(f"unterminated string at offset {i}")
                j += 1
            push("str", i, j + 1)
            i = j + 1
            continue
        if c == "`" or (c == "}" and stack and stack[-1] == "tpl"):
            if c == "}":
                stack.pop()
            j, ended = scan_template(i + 1)
            push("tpl" if ended else "p", i, j, None if ended else "{")
            i = j
            continue
        if c == "{":
            stack.append("{")
        elif c == "}" and stack:
            stack.pop()
        if c.isdigit():
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "._"):
                j += 1
            push("num", i, j)
            i = j
            continue
        if c.isalpha() or c in "_$\\" or ord(c) > 127:
            j = i + 1
            while j < n and (src[j].isalnum() or src[j] in "_$\\" or ord(src[j]) > 127):
                j += 1
            push("id", i, j)
            i = j
            continue
        push("p", i, i + 1)
        i += 1
    if stack:
        raise StripError("unbalanced braces or template substitutions")
    return spans, toks


def strip_js(src: str) -> tuple[str, int]:
    spans, toks = js_lex(src)
    if not spans:
        return src, 0
    out = remove_spans(src, spans, "{")
    spans2, toks2 = js_lex(out)
    if spans2:
        raise StripError("comments remain after stripping")
    if toks != toks2:
        for k, (a, b) in enumerate(zip(toks, toks2)):
            if a != b:
                raise StripError(f"JS token stream changed at token {k}: {a!r} -> {b!r}")
        raise StripError("JS token count changed")
    return out, len(spans)


def css_spans(src: str) -> list[tuple[int, int, str]]:
    spans, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "'\"":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            i = j + 1
            continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            if j < 0:
                raise StripError("unterminated CSS comment")
            spans.append((i, j + 2, ""))
            i = j + 2
            continue
        i += 1
    return spans


def _css_tokens(src: str) -> list[str]:
    no_comments = src
    for a, b, _ in sorted(css_spans(src), reverse=True):
        no_comments = no_comments[:a] + " " + no_comments[b:]
    return no_comments.split()


def strip_css(src: str) -> tuple[str, int]:
    spans = css_spans(src)
    if not spans:
        return src, 0
    out = remove_spans(src, spans, "{")
    if css_spans(out):
        raise StripError("CSS comments remain after stripping")
    if _css_tokens(src) != _css_tokens(out):
        raise StripError("CSS token stream changed")
    return out, len(spans)


BLOCK_RE = re.compile(r"(<(script|style)\b[^>]*>)(.*?)(</\2\s*>)", re.S | re.I)


def strip_html(text: str) -> tuple[str, int]:
    pieces, pos, count = [], 0, 0
    for m in BLOCK_RE.finditer(text):
        outside, n_html = _strip_html_comments(text[pos:m.start()])
        count += n_html
        inner = m.group(3)
        if m.group(2).lower() == "script":
            new_inner, k = strip_js(inner)
        else:
            new_inner, k = strip_css(inner)
        count += k
        pieces += [outside, m.group(1), new_inner, m.group(4)]
        pos = m.end()
    tail, n_html = _strip_html_comments(text[pos:])
    pieces.append(tail)
    return "".join(pieces), count + n_html


HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.S)


def _strip_html_comments(chunk: str) -> tuple[str, int]:
    spans = [(m.start(), m.end(), "") for m in HTML_COMMENT_RE.finditer(chunk)]
    if not spans:
        return chunk, 0
    out = remove_spans(chunk, spans, ">")
    if HTML_COMMENT_RE.search(out):
        raise StripError("HTML comments remain after stripping")
    return out, len(spans)


def targets():
    for p in sorted((ROOT / "app").rglob("*.py")):
        yield p, "py+doc"
    for p in sorted((ROOT / "tests").rglob("*.py")):
        yield p, "py+doc"
    yield ROOT / "app" / "static" / "index.html", "html"
    for p in sorted((ROOT / "tests").rglob("*.js")):
        yield p, "js"
    for p in sorted((ROOT / "demo").glob("*.py")):
        yield p, "py"


def process(path: pathlib.Path, kind: str) -> tuple[str, str, int]:
    text = path.read_text(encoding="utf-8")
    if kind == "py+doc":
        out, k = strip_python(text, docstrings=True)
    elif kind == "py":
        out, k = strip_python(text, docstrings=False)
    elif kind == "html":
        out, k = strip_html(text)
    else:
        out, k = strip_js(text)
    return text, out, k


def run(check_only: bool) -> int:
    failed, changed, clean = [], [], 0
    for path, kind in targets():
        if not path.exists():
            continue
        rel = path.relative_to(ROOT).as_posix()
        try:
            text, out, k = process(path, kind)
        except (StripError, SyntaxError, tokenize.TokenError) as e:
            failed.append(f"{rel}: {e}")
            continue
        if out == text:
            clean += 1
            continue
        changed.append((rel, k))
        if not check_only:
            path.write_text(out, encoding="utf-8", newline="\n")
    verb = "has" if check_only else "stripped"
    for rel, k in changed:
        print(f"  {verb:8} {k:4d} comment(s)/docstring(s)  {rel}")
    for f in failed:
        print(f"  FAIL     {f}")
    print()
    if failed:
        print(f"{len(failed)} file(s) could not be verified and were left untouched.")
        return 1
    if check_only and changed:
        print(f"{len(changed)} file(s) still carry comments. Run: python demo/strip_comments.py")
        return 1
    print(f"no comments: {clean} file(s) already clean, {0 if check_only else len(changed)} stripped")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify only, change nothing")
    sys.exit(run(ap.parse_args().check))
