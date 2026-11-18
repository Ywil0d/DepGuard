import unittest

from core.dependency_parser import (
    parse_requirements_txt,
    parse_pyproject_toml,
)


class DependencyParserTests(unittest.TestCase):

    def test_requirements_parser(self):
        content = """
requests==2.31.0
django>=4.2
flask
numpy==1.26.4
"""

        result = parse_requirements_txt(content)

        self.assertEqual(len(result), 4)

        requests_package = next(
            item for item in result
            if item["name"] == "requests"
        )

        self.assertEqual(
            requests_package["version"],
            "2.31.0",
        )

        self.assertTrue(requests_package["is_pinned"])

        django_package = next(
            item for item in result
            if item["name"] == "django"
        )

        self.assertFalse(django_package["is_pinned"])

    def test_pyproject_parser(self):
        content = """
[project]
name = "test-project"
version = "1.0.0"
dependencies = [
    "requests==2.31.0",
    "flask>=3.0"
]
"""

        result = parse_pyproject_toml(content)

        self.assertEqual(len(result), 2)

        requests_package = next(
            item for item in result
            if item["name"] == "requests"
        )

        self.assertEqual(
            requests_package["version"],
            "2.31.0",
        )

    def test_poetry_parser(self):
        content = """
[tool.poetry.dependencies]
python = "^3.11"
requests = "2.31.0"
django = "^4.2"
"""

        result = parse_pyproject_toml(content)

        self.assertEqual(len(result), 2)

        requests_package = next(
            item for item in result
            if item["name"] == "requests"
        )

        self.assertTrue(requests_package["is_pinned"])

        django_package = next(
            item for item in result
            if item["name"] == "django"
        )

        self.assertFalse(django_package["is_pinned"])


if __name__ == "__main__":
    unittest.main()