import argparse
import sys
from pathlib import Path

from md_to_pdf.converter import MarkdownToPdf


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="md-to-pdf",
        description="Convert a Markdown file to PDF.",
    )
    parser.add_argument("input", type=Path, help="Source Markdown file")
    parser.add_argument("-o", "--output", type=Path, default=None, help="Output PDF path")
    parser.add_argument(
        "--style",
        choices=["light", "dark"],
        default="light",
        help="Color theme (default: light)",
    )
    args = parser.parse_args()

    input_path: Path = args.input.resolve()
    if not input_path.is_file():
        print(f"error: {input_path} does not exist or is not a file", file=sys.stderr)
        sys.exit(1)

    output_path: Path = args.output.resolve() if args.output else input_path.with_suffix(".pdf")

    md_text = input_path.read_text(encoding="utf-8")
    MarkdownToPdf(args.style).convert(md_text, output_path, base_url=input_path.parent)
    print(f"PDF written to {output_path}")


if __name__ == "__main__":
    main()
