"""Static checks for the Docker image and GHCR workflow (no docker required)."""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"
WORKFLOW = ROOT / ".github" / "workflows" / "docker.yml"


class DockerfileTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = DOCKERFILE.read_text(encoding="utf-8")

    def _from_line(self) -> str:
        for line in self.text.splitlines():
            if line.startswith("FROM "):
                return line
        self.fail("no FROM instruction")

    def test_base_image_is_python_312_slim(self):
        self.assertEqual(self._from_line(), "FROM python:3.12-slim")

    def test_final_user_is_non_root(self):
        users = [line.split()[1] for line in self.text.splitlines() if line.startswith("USER ")]
        self.assertTrue(users, "Dockerfile must set USER")
        self.assertNotIn(users[-1], {"root", "0"})
        self.assertEqual(users[-1], "agentsec")

    def test_entrypoint_is_agentsec(self):
        self.assertIn('ENTRYPOINT ["agentsec"]', self.text)

    def test_installs_with_no_cache(self):
        self.assertIn("pip install", self.text)
        self.assertIn("--no-cache-dir", self.text)

    def test_uses_copy_not_add(self):
        for line in self.text.splitlines():
            self.assertFalse(line.startswith("ADD "), line)

    def test_no_embedded_credentials(self):
        # Image metadata may mention "secret leaks"; look for assignment-style leaks.
        for line in self.text.splitlines():
            if line.lstrip().startswith("#"):
                continue
            self.assertIsNone(re.search(r"(API_KEY|PASSWORD|TOKEN)\s*=\s*\S+", line), line)


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding="utf-8")

    def test_publishes_to_ghcr_with_github_token(self):
        self.assertIn("ghcr.io/dunkleschitz/agentsec", self.text)
        self.assertIn("secrets.GITHUB_TOKEN", self.text)
        self.assertIn("packages: write", self.text)

    def test_triggers_on_main_and_version_tags(self):
        self.assertIn("branches: [main]", self.text)
        self.assertIn('tags: ["v*"]', self.text)

    def test_pull_requests_build_but_do_not_push(self):
        self.assertIn("pull_request:", self.text)
        self.assertIn("github.event_name != 'pull_request'", self.text)
        self.assertIn("push: ${{ github.event_name != 'pull_request' }}", self.text)


if __name__ == "__main__":
    unittest.main()
