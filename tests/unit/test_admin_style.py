"""The interface's one stylesheet.

The stylesheet is the design's, taken unchanged, followed by a marked Maildivvy section
for what the design never had. The section speaks only in the design's tokens: a colour
in it is a `var(--...)`, never a hex value of its own. The page stays light, and the
stylesheet fetches nothing: no `@import`, no `url(`.
"""

import re

from flask import Flask

from maildivvy.admin import app as application
from maildivvy.admin import style

RAW_HEX = re.compile(r"#[0-9a-fA-F]{3,8}\b")


def test_the_maildivvy_section_uses_only_the_designs_tokens():
    assert RAW_HEX.findall(style.MAILDIVVY) == []
    assert "rgb" not in style.MAILDIVVY and "hsl" not in style.MAILDIVVY


def test_the_page_is_light_and_the_stylesheet_fetches_nothing():
    assert re.search(r":root\{\s*color-scheme: light;", style.STYLESHEET)
    assert "prefers-color-scheme" not in style.STYLESHEET
    assert "@import" not in style.STYLESHEET
    assert "url(" not in style.STYLESHEET


def test_every_page_carries_the_stylesheet_as_it_is():
    made = Flask("maildivvy-test")
    application.register(made)
    application.guard_every_endpoint(made)
    html = made.test_client().get("/sign-in").get_data(as_text=True)
    # the font stacks' quotes and the selectors' `>` reach the browser unescaped
    assert f"<style>{style.STYLESHEET}</style>" in html
