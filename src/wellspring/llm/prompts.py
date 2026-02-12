from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader

_PROMPT_DIR = Path(__file__).parent / "prompts"

_env = Environment(
    loader=FileSystemLoader(str(_PROMPT_DIR)),
    autoescape=False,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_prompt(template_name: str, **kwargs: object) -> str:
    template = _env.get_template(template_name)
    return template.render(**kwargs)
