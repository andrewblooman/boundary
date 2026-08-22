from boundary.reporters.json_reporter import to_json
from boundary.reporters.markdown_reporter import to_markdown, to_table
from boundary.reporters.sarif_reporter import to_sarif

FORMATS = {
    "json": to_json,
    "sarif": to_sarif,
    "md": to_markdown,
    "table": to_table,
}

__all__ = ["FORMATS", "to_json", "to_markdown", "to_sarif", "to_table"]
