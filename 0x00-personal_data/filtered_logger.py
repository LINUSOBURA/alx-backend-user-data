#!/usr/bin/env python3
"""Filter Data"""

import logging
import os
import re
from typing import List

import mysql.connector


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
    """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """Format the log record by filtering sensitive data."""
        return filter_datum(self.fields, self.REDACTION,
                            super().format(record), self.SEPARATOR)


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """filter data to reduct"""
    pattern = r"(" + "|".join(
        [f"(?<={field}=)[^{separator}]+" for field in fields]) + r")"
    reducted = re.sub(pattern, redaction, message)
    return reducted


PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def get_logger() -> logging.Logger:
    """Get a logger instance for the "user_data" logger.
"""
    logger = logging.getLogger("user_data")
    logger.propagate = False
    logger.setLevel(logging.INFO)
    handler = logging.StreamHandler()
    handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Connects to a MySQL database using the credentials provided
    in the environment variables"""
    mydb = mysql.connector.connect(
        host=os.getenv("PERSONAL_DATA_DB_HOST", "localhost"),
        user=os.getenv("PERSONAL_DATA_DB_USERNAME", "root"),
        password=os.getenv("PERSONAL_DATA_DB_PASSWORD", ""),
        database=os.getenv("PERSONAL_DATA_DB_NAME"),
    )
    return mydb


def main() -> None:
    """Executes a SELECT query on the "users" table in the
    database and logs the results."""
    db = get_db()
    mycursor = db.cursor()
    mycursor.execute("SELECT * FROM users;")
    headers = mycursor.column_names
    logger = get_logger()
    for row in mycursor:
        filtered = ""
        for f, p in zip(row, headers):
            filtered += f'{p}={(f)}; '
        logger.info(filtered)
    mycursor.close()
    db.close()


if __name__ == "__main__":
    main()
