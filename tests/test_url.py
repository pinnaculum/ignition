"""
This Source Code Form is subject to the terms of the
Mozilla Public License, v. 2.0. If a copy of the MPL
was not distributed with this file, You can obtain one
at http://mozilla.org/MPL/2.0/.
"""
# pylint:disable=missing-function-docstring

import pytest

from ignition.url import URL


@pytest.mark.parametrize(
    "test_url",
    [
        "gemini://gemini.circumlunar.space/",
        "//gemini.circumlunar.space/",
        "gemini://gemini.circumlunar.space:1965/",
        "//gemini.circumlunar.space:1965/",
        "  gemini://gemini.circumlunar.space:1965/",
        "  //gemini.circumlunar.space:1965/",
    ],
)
def test_standard_gemini_url(test_url):
    final_url = URL(test_url)
    assert str(final_url) == "gemini://gemini.circumlunar.space/"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gemini.circumlunar.space"
    assert final_url.port() == 1965
    assert final_url.path() == "/"
    assert final_url.query() == ""


def test_url_with_different_scheme():
    final_url = URL("https://gemini.circumlunar.space/")
    assert str(final_url) == "https://gemini.circumlunar.space/"
    assert final_url.protocol() == "https://"
    assert final_url.host() == "gemini.circumlunar.space"
    assert final_url.port() == 1965
    assert final_url.path() == "/"
    assert final_url.query() == ""


def test_url_with_nonstandard_port():
    final_url = URL("gemini://gemini.circumlunar.space:80/")
    assert str(final_url) == "gemini://gemini.circumlunar.space:80/"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gemini.circumlunar.space"
    assert final_url.port() == 80
    assert final_url.path() == "/"
    assert final_url.query() == ""


@pytest.mark.parametrize("test_path", ["", "/", "/test/path.gmi"])
@pytest.mark.parametrize("test_query", ["", "abc", "user=name"])
def test_url_with_basic_paths_and_queries(test_path, test_query):
    test_url = "gemini://gemini.circumlunar.space" + test_path
    if test_query:
        test_url += "?" + test_query

    final_url = URL(test_url)

    assert str(final_url) == test_url
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gemini.circumlunar.space"
    assert final_url.port() == 1965
    assert final_url.path() == test_path
    assert final_url.query() == test_query


def test_url_with_convoluted_path():
    final_url = URL("gemini://gemini.circumlunar.space/test/./test2/../path.gmi")
    assert str(final_url) == "gemini://gemini.circumlunar.space/test/path.gmi"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gemini.circumlunar.space"
    assert final_url.port() == 1965
    assert final_url.path() == "/test/path.gmi"
    assert final_url.query() == ""


def test_standard_gemini_url_with_referer():
    final_url = URL(
        "gemini://gus.guru/", referer_url="gemini://gemini.circumlunar.space/"
    )
    assert str(final_url) == "gemini://gus.guru/"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gus.guru"
    assert final_url.port() == 1965
    assert final_url.path() == "/"
    assert final_url.query() == ""


def test_url_without_scheme_with_referer():
    final_url = URL("//gus.guru/", referer_url="gemini://gemini.circumlunar.space/")
    assert str(final_url) == "gemini://gus.guru/"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gus.guru"
    assert final_url.port() == 1965
    assert final_url.path() == "/"
    assert final_url.query() == ""


def test_absolute_path_url():
    final_url = URL("/home", referer_url="gemini://gus.guru/search/page2")
    assert str(final_url) == "gemini://gus.guru/home"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gus.guru"
    assert final_url.port() == 1965
    assert final_url.path() == "/home"
    assert final_url.query() == ""


def test_relative_path_url_with_referer():
    final_url = URL("page1", referer_url="gemini://gus.guru/search/page2")
    assert str(final_url) == "gemini://gus.guru/search/page1"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gus.guru"
    assert final_url.port() == 1965
    assert final_url.path() == "/search/page1"
    assert final_url.query() == ""


def test_relative_path_url_with_trailing_slash_with_referer():
    final_url = URL("page1/", referer_url="gemini://gus.guru/")
    assert str(final_url) == "gemini://gus.guru/page1/"
    assert final_url.protocol() == "gemini://"
    assert final_url.host() == "gus.guru"
    assert final_url.port() == 1965
    assert final_url.path() == "/page1/"
    assert final_url.query() == ""
