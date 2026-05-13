![IMAGE](images/md2pdf-logo.png)

md2pdf convert Markdown files to PDF with syntax-highlighted code blocks and styled tables.

## Requirements

- Python 3.11 or newer
- System libraries required by [WeasyPrint](https://weasyprint.org/), will be installed when running `python3 -m pip install -e .` (see installation section)
- On macOS:
```bash
brew install pango
```
- On Debian/Ubuntu:
```bash
sudo apt install libpango-1.0-0 libpangoft2-1.0-0
```

## Installation

```bash
cd md-to-pdf
python3 -m pip install -e .
```

This installs the `md-to-pdf` command and all required dependencies into your active Python environment.

## Usage

```bash
# Output PDF next to the source file (report.md → report.pdf)
md-to-pdf report.md

# Explicit output path
md-to-pdf report.md -o /path/to/output.pdf

# Dark theme
md-to-pdf report.md --style dark
```

### Options

| Flag | Default | Description |
|------|---------|-------------|
| `-o`, `--output` | Same directory as input, `.pdf` extension | Output PDF path |
| `--style` | `light` | Color theme: `light` or `dark` |

## What renders well

- **Tables** — full borders, distinct header row, alternating row shading
- **Code blocks** — per-language syntax highlighting (Friendly theme for light, Monokai for dark), long lines wrap cleanly
- **Inline code** — tinted background with border
- **Headings** — h1/h2 with bottom borders for visual hierarchy
- **Blockquotes** — left border with subtle background
- **Task lists** — GFM-style `- [ ]` / `- [x]` checkboxes