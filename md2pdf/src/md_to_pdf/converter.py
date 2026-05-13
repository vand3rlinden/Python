from __future__ import annotations

import html as html_module
from pathlib import Path
from typing import Literal

import weasyprint
from markdown_it import MarkdownIt
from mdit_py_plugins.tasklists import tasklists_plugin
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import get_lexer_by_name, guess_lexer, TextLexer
from pygments.util import ClassNotFound

from md_to_pdf.styles import DARK_CSS, LIGHT_CSS

ThemeName = Literal["light", "dark"]

_PYGMENTS_LIGHT = HtmlFormatter(nowrap=True, style="friendly")
_PYGMENTS_DARK = HtmlFormatter(nowrap=True, style="monokai")


def _make_highlighter(theme: ThemeName):
    formatter = _PYGMENTS_LIGHT if theme == "light" else _PYGMENTS_DARK

    def _highlight(code: str, lang: str, _attrs: str) -> str:
        if lang:
            try:
                lexer = get_lexer_by_name(lang)
            except ClassNotFound:
                lexer = TextLexer()
        else:
            try:
                lexer = guess_lexer(code)
            except ClassNotFound:
                lexer = TextLexer()
        highlighted = highlight(code, lexer, formatter)
        lang_class = f"language-{html_module.escape(lang)}" if lang else ""
        return f'<pre class="highlight"><code class="{lang_class}">{highlighted}</code></pre>\n'

    return _highlight


def _build_md(theme: ThemeName) -> MarkdownIt:
    md = MarkdownIt("commonmark", options_update={"highlight": _make_highlighter(theme)})
    md.enable("table")
    # tasklists_plugin adds GFM-style checkboxes, handy for investigation notes
    tasklists_plugin(md)
    return md


def _pygments_css(theme: ThemeName) -> str:
    formatter = _PYGMENTS_LIGHT if theme == "light" else _PYGMENTS_DARK
    return formatter.get_style_defs("pre.highlight")


def _wrap_html(body: str, css: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<style>
{css}
</style>
</head>
<body>
{body}
</body>
</html>"""


class MarkdownToPdf:
    def __init__(self, theme: ThemeName = "light") -> None:
        self._theme = theme
        self._md = _build_md(theme)
        base_css = LIGHT_CSS if theme == "light" else DARK_CSS
        self._css = (
            base_css
            + "\n"
            + _pygments_css(theme)
            + "\npre.highlight .err { color: inherit; background: transparent; border: none; }"
        )

    def convert(self, md_text: str, output_path: Path, base_url: Path | None = None) -> None:
        body = self._md.render(md_text)
        full_html = _wrap_html(body, self._css)
        pdf_bytes = weasyprint.HTML(string=full_html, base_url=str(base_url) if base_url else None).write_pdf()
        output_path.write_bytes(pdf_bytes)
