from __future__ import annotations

import pytest

from h1vault.api.models import filter_program, program_handle


def test_exact_normalized_handle_no_substring(report_factory) -> None:
    reports = [
        report_factory("1", program="Example-Program"),
        report_factory("2", program="example-program-extra"),
        report_factory("3", program="other"),
    ]
    assert [item["id"] for item in filter_program(reports, " example-program ")] == ["1"]


@pytest.mark.parametrize(
    "relationship",
    [None, {}, {"data": None}, {"data": {}}, {"data": {"attributes": None}}],
)
def test_missing_or_null_program_is_tolerated(report_factory, relationship) -> None:
    report = report_factory()
    if relationship is None:
        del report["relationships"]["program"]
    else:
        report["relationships"]["program"] = relationship
    assert program_handle(report) is None
    assert filter_program([report], "example-program") == []


def test_zero_matching_reports(report_factory) -> None:
    assert filter_program([report_factory(program="other")], "wanted") == []
