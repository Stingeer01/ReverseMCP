from __future__ import annotations

import re
import sys
from pathlib import Path


FRONTMATTER = re.compile(r"^---\s*\n(?P<body>.*?)\n---\s*\n", re.DOTALL)
FIELD = re.compile(r"^(?P<key>[a-z_]+):\s*(?P<value>.+)$", re.MULTILINE)
LINK = re.compile(r"\[[^]]+\]\((?!https?://|#)(?P<path>[^)]+)\)")


def validate_skill(skill: Path) -> list[str]:
    errors: list[str] = []
    source = skill / "SKILL.md"
    if not source.is_file():
        return [f"{skill.name}: missing SKILL.md"]
    text = source.read_text(encoding="utf-8")
    match = FRONTMATTER.match(text)
    if match is None:
        return [f"{skill.name}: invalid frontmatter"]
    fields = {item.group("key"): item.group("value").strip(' "')
              for item in FIELD.finditer(match.group("body"))}
    if fields.get("name") != skill.name:
        errors.append(f"{skill.name}: frontmatter name does not match directory")
    if len(fields.get("description", "")) < 40:
        errors.append(f"{skill.name}: description is not discriminating")
    if "TODO" in text or "placeholder" in text.lower():
        errors.append(f"{skill.name}: unfinished placeholder")
    for link in LINK.finditer(text):
        target = (skill / link.group("path")).resolve()
        if not target.is_file():
            errors.append(f"{skill.name}: broken reference {link.group('path')}")
    metadata = skill / "agents" / "openai.yaml"
    if not metadata.is_file():
        errors.append(f"{skill.name}: missing agents/openai.yaml")
    elif f"${skill.name}" not in metadata.read_text(encoding="utf-8") and skill.name != "reverse-analysis":
        errors.append(f"{skill.name}: default prompt does not name the skill")
    if skill.name != "reverse-analysis":
        references = list((skill / "references").glob("*.md"))
        if not references:
            errors.append(f"{skill.name}: missing progressive-disclosure reference")
        elif not any("https://" in item.read_text(encoding="utf-8") for item in references):
            errors.append(f"{skill.name}: reference has no authoritative source links")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else "skills").resolve()
    errors = [error for skill in sorted(root.iterdir()) if skill.is_dir()
              for error in validate_skill(skill)]
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"Validated {sum(1 for path in root.iterdir() if path.is_dir())} knowledge skills")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
