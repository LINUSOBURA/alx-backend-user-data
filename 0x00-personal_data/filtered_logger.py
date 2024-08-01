#!/usr/bin/env python3
"""Filter Data"""

import logging
import re
from typing import List


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: list) -> None:
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record by filtering sensitive data."""
        NotImplementedError
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """filter data to reduct"""
    pattern = r"(" + "|".join(
        [f"(?<={field}=)[^{separator}]+" for field in fields]) + r")"
    reducted = re.sub(pattern, redaction, message)
    return reducted
