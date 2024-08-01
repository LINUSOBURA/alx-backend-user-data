#!/usr/bin/env python3
"""Filter Data"""

import re


def filter_datum(fields, redaction, message, separator) -> str:
    """filter data to reduct"""
    pattern = r"(" + "|".join(
        [f"(?<={field}=)[^{separator}]+" for field in fields]) + r")"

    reducted = re.sub(pattern, redaction, message)

    return reducted
