"""Exercise release guards without credentials, network access, or uploads."""

import subprocess
import tempfile
import unittest
from pathlib import Path


HELPERS = Path(__file__).with_name("release.sh").resolve()

# Replace external commands, not the release guards under test.
MOCK_COMMANDS = r"""
curl() {
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  printf '%s' "$HTTP_STATUS"
  return "$CURL_EXIT"
}
gh() {
  printf '%s\n' "$*" >> "$COMMAND_LOG"
  if [ "$GH_EXIT" != 0 ]; then return "$GH_EXIT"; fi
  case "$*" in
    *commits/*) printf '%s\n' "$REMOTE_COMMIT" ;;
    *"/attempts/$SUCCESSFUL_ATTEMPT/jobs?"*)
      if [ "$SUCCESSFUL_ATTEMPT" != 0 ]; then printf '7\n'; fi ;;
  esac
  return 0
}
npm() {
  printf 'npm %s\n' "$*" >> "$COMMAND_LOG"
  printf '%s\n' "$CHANNEL_VERSION"
  return "$NPM_EXIT"
}
pnpm() {
  printf 'pnpm %s\n' "$*" >> "$COMMAND_LOG"
  return "$SEMVER_EXIT"
}
"""


class ReleaseGuardTests(unittest.TestCase):
    def run_guard(self, command, **overrides):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "commands"
            env = {
                "PATH": "/usr/bin:/bin",
                "RELEASE_HELPERS": str(HELPERS),
                "COMMAND_LOG": str(log),
                "GH_REPO": "nearai/inference-sdk",
                "RELEASE_TAG": "npm-v1.2.3",
                "RELEASE_VERSION": "1.2.3",
                "NPM_TAG": "latest",
                "CHANNEL_VERSION": "1.2.2",
                "NPM_EXIT": "0",
                "SEMVER_EXIT": "0",
                "GITHUB_SHA": "a" * 40,
                "GITHUB_RUN_ID": "12345",
                "GITHUB_RUN_ATTEMPT": "1",
                "REMOTE_COMMIT": "a" * 40,
                "HTTP_STATUS": "200",
                "CURL_EXIT": "0",
                "GH_EXIT": "0",
                "SUCCESSFUL_ATTEMPT": "0",
                **overrides,
            }
            result = subprocess.run(
                [
                    "/bin/bash",
                    "-e",
                    "-o",
                    "pipefail",
                    "-c",
                    MOCK_COMMANDS + '\nsource "$RELEASE_HELPERS"\n' + command,
                ],
                cwd=directory,
                env=env,
                capture_output=True,
                text=True,
            )
            calls = log.read_text() if log.exists() else ""
            return result, calls

    def test_only_404_means_a_registry_version_is_absent(self):
        for status, expected in [("200", "true"), ("404", "false")]:
            with self.subTest(status=status):
                result, calls = self.run_guard(
                    "registry_version_exists https://registry.example/package/1.2.3",
                    HTTP_STATUS=status,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)
                self.assertIn("--user-agent nearai-inference-sdk-release", calls)

    def test_registry_http_and_network_errors_stop_before_upload(self):
        for status, code in [("403", "0"), ("429", "0"), ("503", "0"), ("000", "7")]:
            with self.subTest(status=status):
                result, _ = self.run_guard(
                    "published=$(registry_version_exists https://registry.example/version)\necho upload",
                    HTTP_STATUS=status,
                    CURL_EXIT=code,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("upload", result.stdout)

    def test_tag_must_still_point_to_the_run_commit(self):
        for commit, valid in [("a" * 40, True), ("b" * 40, False)]:
            with self.subTest(commit=commit):
                result, _ = self.run_guard(
                    "verify_release_tag\necho publish",
                    REMOTE_COMMIT=commit,
                )
                self.assertEqual(result.returncode == 0, valid, result.stderr)
                self.assertEqual("publish" in result.stdout, valid)

    def test_first_npm_channel_release_needs_no_version_comparison(self):
        result, calls = self.run_guard(
            "verify_npm_channel\necho upload", HTTP_STATUS="404"
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("upload", result.stdout)
        self.assertNotIn("npm view", calls)
        self.assertNotIn("pnpm dlx", calls)

    def test_npm_upload_requires_semver_check_on_fresh_runs_and_retries(self):
        for tag, current, candidate, exit_code in [
            ("latest", "1.2.3", "1.2.4", "0"),
            ("latest", "1.2.3", "1.2.2", "1"),
            ("next", "1.2.3-rc.9", "1.2.3-rc.10", "0"),
            ("next", "1.2.3-rc.10", "1.2.3-rc.9", "1"),
        ]:
            for attempt in ["1", "2"]:
                with self.subTest(tag=tag, attempt=attempt, candidate=candidate):
                    result, calls = self.run_guard(
                        "verify_npm_channel\necho upload",
                        NPM_TAG=tag,
                        CHANNEL_VERSION=current,
                        RELEASE_VERSION=candidate,
                        GITHUB_RUN_ATTEMPT=attempt,
                        SEMVER_EXIT=exit_code,
                    )
                    self.assertEqual(result.returncode == 0, exit_code == "0")
                    self.assertEqual("upload" in result.stdout, exit_code == "0")
                    self.assertIn(
                        f"npm view @nearai/inference-sdk@{tag} version", calls
                    )
                    self.assertIn(
                        "pnpm dlx semver@7.8.5 --include-prerelease "
                        f"--range >={current} {candidate}",
                        calls,
                    )

    def test_npm_channel_lookup_failures_stop_upload(self):
        for failure in [
            {"HTTP_STATUS": "503"},
            {"CURL_EXIT": "7"},
            {"NPM_EXIT": "1"},
            {"CHANNEL_VERSION": ""},
            {"SEMVER_EXIT": "127"},
        ]:
            with self.subTest(failure=failure):
                result, _ = self.run_guard("verify_npm_channel\necho upload", **failure)
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn("upload", result.stdout)

    def test_tag_lookup_errors_stop_publication(self):
        result, _ = self.run_guard("verify_release_tag\necho publish", GH_EXIT="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("publish", result.stdout)

    def test_existing_version_is_rejected_on_a_fresh_run(self):
        result, calls = self.run_guard(
            "require_verified_retry publish-npm 'Upload npm package'",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("without a successful upload", result.stderr)
        self.assertEqual(calls, "")

    def test_retries_need_a_successful_upload_from_the_same_run(self):
        for job, step in [
            ("publish-npm", "Upload npm package"),
            ("publish-pypi", "Upload Python distributions"),
            ("publish-crates", "Upload crate"),
        ]:
            for uploaded in [False, True]:
                with self.subTest(job=job, uploaded=uploaded):
                    result, calls = self.run_guard(
                        f"require_verified_retry {job} '{step}'",
                        GITHUB_RUN_ATTEMPT="2",
                        SUCCESSFUL_ATTEMPT="1" if uploaded else "0",
                    )
                    self.assertEqual(result.returncode == 0, uploaded, result.stderr)
                    self.assertIn("/actions/runs/12345/attempts/1/jobs", calls)
                    self.assertIn(f'select(.name == "{job}")', calls)
                    self.assertIn(
                        f'select(.name == "{step}" and .conclusion == "success")', calls
                    )

    def test_a_later_retry_can_find_the_original_successful_upload(self):
        result, calls = self.run_guard(
            "require_verified_retry publish-npm 'Upload npm package'",
            GITHUB_RUN_ATTEMPT="3",
            SUCCESSFUL_ATTEMPT="1",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("/attempts/2/jobs", calls)
        self.assertIn("/attempts/1/jobs", calls)

    def test_unavailable_run_history_does_not_authorize_skipping_upload(self):
        result, _ = self.run_guard(
            "require_verified_retry publish-npm 'Upload npm package'\necho skip-upload",
            GITHUB_RUN_ATTEMPT="2",
            GH_EXIT="1",
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("skip-upload", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
