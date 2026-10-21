"""Release planning and finalization tests; all GitHub calls use a local stub."""

import itertools
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from release_plan import LANGUAGES, plan_release

SCRIPTS = Path(__file__).resolve().parent


class ReleasePlanTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def manifests(self, versions):
        for language, version in versions.items():
            path, content = {
                "javascript": ("js/package.json", json.dumps({"version": version})),
                "python": ("py/pyproject.toml", f'[project]\nversion = "{version}"\n'),
                "rust": ("rs/Cargo.toml", f'[package]\nversion = "{version}"\n'),
                "go": ("go/go.mod", "module github.com/nearai/inference-sdk/go\n"),
            }[language]
            target = self.root / path
            target.parent.mkdir(exist_ok=True)
            target.write_text(content, encoding="utf-8")

    def inputs(self, version="0.2.0-rc.1", languages=LANGUAGES):
        return {"version": version, **dict.fromkeys(languages, True)}

    def run_cli(self, inputs):
        return subprocess.run(
            [sys.executable, str(SCRIPTS / "release_plan.py")],
            cwd=self.root,
            env={
                **os.environ,
                "RELEASE_INPUTS": json.dumps(inputs),
                "GITHUB_OUTPUT": str(self.root / "output"),
                "GITHUB_STEP_SUMMARY": str(self.root / "summary"),
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def test_all_languages_rc_versions_and_tags(self):
        self.manifests(
            {
                language: "0.2.0rc1" if language == "python" else "0.2.0-rc.1"
                for language in LANGUAGES
            }
        )
        result = self.run_cli(self.inputs())
        self.assertEqual(result.returncode, 0, result.stderr)
        outputs = dict(
            line.split("=", 1)
            for line in (self.root / "output").read_text().splitlines()
        )
        self.assertEqual(json.loads(outputs["languages"]), list(LANGUAGES))
        self.assertEqual(
            json.loads(outputs["registry-languages"]), ["javascript", "python", "rust"]
        )
        self.assertEqual(outputs["prerelease"], "true")
        self.assertEqual(outputs["npm-tag"], "next")
        packages = json.loads(outputs["packages"])
        self.assertEqual(
            packages,
            {
                "javascript": {
                    "version": "0.2.0-rc.1",
                    "tag": "javascript-v0.2.0-rc.1",
                },
                "python": {"version": "0.2.0rc1", "tag": "python-v0.2.0rc1"},
                "rust": {"version": "0.2.0-rc.1", "tag": "rust-v0.2.0-rc.1"},
                "go": {"version": "0.2.0-rc.1", "tag": "go/v0.2.0-rc.1"},
            },
        )
        self.assertIn(
            "| python | `0.2.0rc1` | `python-v0.2.0rc1` |",
            (self.root / "summary").read_text(),
        )

    def test_stable_version_keeps_latest_channel(self):
        self.manifests(dict.fromkeys(LANGUAGES, "0.2.0"))
        plan = plan_release(self.root, self.inputs("0.2.0"))
        self.assertFalse(plan["prerelease"])
        self.assertEqual(plan["npm-tag"], "latest")
        self.assertEqual({p["version"] for p in plan["packages"].values()}, {"0.2.0"})

    def test_every_nonempty_selection_ignores_unselected_manifests(self):
        for count in range(1, 5):
            for selected in itertools.combinations(LANGUAGES, count):
                with (
                    self.subTest(selected=selected),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    self.root = Path(directory)
                    self.manifests(dict.fromkeys(selected, "0.2.0"))
                    inputs = {
                        "version": "0.2.0",
                        **{language: language in selected for language in LANGUAGES},
                    }
                    plan = plan_release(self.root, inputs)
                    self.assertEqual(list(plan["packages"]), list(selected))
                    self.assertEqual(plan["languages"], list(selected))
                    self.assertEqual(
                        plan["registry-languages"],
                        [language for language in selected if language != "go"],
                    )

    def test_nothing_selected_is_rejected_without_outputs(self):
        result = self.run_cli(self.inputs(languages=()))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Select at least one SDK", result.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_mismatched_python_manifest_blocks_the_whole_batch(self):
        self.manifests(
            {
                "javascript": "0.2.0-rc.1",
                "python": "0.2.0",
                "rust": "0.2.0-rc.1",
                "go": "0.2.0-rc.1",
            }
        )
        result = self.run_cli(self.inputs())
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Requested python version '0.2.0rc1'", result.stderr)
        self.assertFalse((self.root / "output").exists())
        self.assertFalse((self.root / "summary").exists())

    def test_semver_spelling_in_python_manifest_is_rejected(self):
        self.manifests({"python": "0.2.0-rc.1"})
        with self.assertRaisesRegex(ValueError, "does not match py/pyproject.toml"):
            plan_release(self.root, self.inputs(languages=("python",)))

    def test_alpha_beta_and_multidigit_rc_conversion(self):
        for suffix, expected in (
            ("alpha.0", "a0"),
            ("beta.2", "b2"),
            ("rc.10", "rc10"),
        ):
            with self.subTest(suffix=suffix):
                self.manifests({"python": "0.2.0" + expected})
                plan = plan_release(
                    self.root, self.inputs("0.2.0-" + suffix, ("python",))
                )
                self.assertEqual(
                    plan["packages"]["python"]["version"], "0.2.0" + expected
                )
                self.assertTrue(plan["prerelease"])

    def test_unrepresentable_python_prerelease_is_rejected(self):
        self.manifests({"python": "0.2.0rc1"})
        for version in ("0.2.0-preview.1", "0.2.0-rc.1.extra", "0.2.0-rc1"):
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(ValueError, "Python prereleases require"),
            ):
                plan_release(self.root, self.inputs(version, ("python",)))

    def test_other_semver_prereleases_still_work_without_python(self):
        self.manifests({"javascript": "0.2.0-preview.1", "rust": "0.2.0-preview.1"})
        plan = plan_release(
            self.root, self.inputs("0.2.0-preview.1", ("javascript", "rust"))
        )
        self.assertEqual(plan["packages"]["javascript"]["version"], "0.2.0-preview.1")
        self.assertTrue(plan["prerelease"])

    def test_invalid_shared_versions_are_rejected(self):
        for version in (
            "v0.2.0",
            "0.2",
            "01.2.0",
            "0.2.0-rc.01",
            "0.2.0+build",
            "0.2.0rc1",
            "0.2.0\n",
        ):
            with (
                self.subTest(version=version),
                self.assertRaisesRegex(ValueError, "Use X.Y.Z"),
            ):
                plan_release(self.root, self.inputs(version))

    def test_go_major_version_and_module_path_checks_are_preserved(self):
        self.manifests({"go": "2.0.0"})
        with self.assertRaisesRegex(ValueError, "new /vN module path"):
            plan_release(self.root, self.inputs("2.0.0", ("go",)))
        (self.root / "go/go.mod").write_text("module example.com/wrong\n")
        with self.assertRaisesRegex(ValueError, "Unexpected Go module path"):
            plan_release(self.root, self.inputs("0.2.0", ("go",)))


class ReleaseFinalizationTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.log = self.root / "calls.jsonl"
        self.summary = self.root / "summary"
        stub = self.root / "gh"
        stub.write_text(
            f"#!{sys.executable}\n"
            + """
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
with open(os.environ["GH_STUB_LOG"], "a") as log:
    print(json.dumps(args), file=log)
state_path = Path(os.environ["GH_STUB_LOG"] + ".published")
published = json.loads(state_path.read_text()) if state_path.exists() else []
if args[0] == "api":
    print("other-commit" if os.environ.get("MISMATCH_TAG", "<none>") in args[1] else os.environ["GITHUB_SHA"])
elif args[:2] == ["release", "view"]:
    print("false" if args[2] in published else "true")
elif args[:2] == ["release", "edit"]:
    if args[2] == os.environ.get("FAIL_EDIT_TAG"):
        sys.exit(1)
    published.append(args[2])
    state_path.write_text(json.dumps(published))
else:
    sys.exit("Unexpected GitHub operation: " + repr(args))
"""
        )
        stub.chmod(0o755)
        self.packages = {
            language: {"tag": "go/v0.2.0" if language == "go" else f"{language}-v0.2.0"}
            for language in LANGUAGES
        }

    def finalize(self, results, packages=None, **extra_env):
        return subprocess.run(
            [
                "bash",
                "-e",
                "-o",
                "pipefail",
                "-c",
                'source "$1"; publish_github_releases',
                "bash",
                str(SCRIPTS / "release.sh"),
            ],
            env={
                **os.environ,
                "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
                "GH_STUB_LOG": str(self.log),
                "GITHUB_STEP_SUMMARY": str(self.summary),
                "GH_REPO": "example/sdk",
                "GH_TOKEN": "test-token",
                "GITHUB_SHA": "release-commit",
                "RELEASE_PACKAGES": json.dumps(
                    self.packages if packages is None else packages
                ),
                "PUBLISH_RESULTS": json.dumps(results),
                **extra_env,
            },
            capture_output=True,
            text=True,
            check=False,
        )

    def edits(self):
        if not self.log.exists():
            return []
        return [
            call
            for line in self.log.read_text().splitlines()
            if (call := json.loads(line))[:2] == ["release", "edit"]
        ]

    def test_partial_success_finalizes_only_successful_publishers(self):
        result = self.finalize(
            {
                "javascript": "success",
                "python": "failure",
                "rust": "skipped",
                "go": "success",
            }
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.edits(),
            [
                ["release", "edit", "javascript-v0.2.0", "--draft=false"],
                ["release", "edit", "go/v0.2.0", "--draft=false", "--latest=false"],
            ],
        )
        self.assertIn("| python | failure | skipped |", self.summary.read_text())

    def test_failed_finalization_does_not_block_other_languages(self):
        result = self.finalize(
            dict.fromkeys(LANGUAGES, "success"), FAIL_EDIT_TAG="javascript-v0.2.0"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(len(self.edits()), 4)
        self.assertIn("| javascript | success | failed |", self.summary.read_text())
        self.assertIn("| go | success | published |", self.summary.read_text())
        retry = self.finalize(dict.fromkeys(LANGUAGES, "success"))
        self.assertEqual(retry.returncode, 0, retry.stderr)
        self.assertEqual(len(self.edits()), 5)
        self.assertEqual(self.edits()[-1][2], "javascript-v0.2.0")

    def test_changed_tag_is_rejected_before_editing_that_release(self):
        result = self.finalize(
            dict.fromkeys(LANGUAGES, "success"), MISMATCH_TAG="javascript-v0.2.0"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no longer points to the workflow commit", result.stderr)
        self.assertEqual(len(self.edits()), 3)
        self.assertNotIn("javascript-v0.2.0", [call[2] for call in self.edits()])

    def test_go_only_release_and_repeat_finalization(self):
        for _ in range(2):
            result = self.finalize({"go": "success"}, {"go": self.packages["go"]})
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            self.edits(),
            [["release", "edit", "go/v0.2.0", "--draft=false", "--latest=false"]],
        )

    def test_no_successful_publishers_makes_no_github_calls(self):
        result = self.finalize(dict.fromkeys(LANGUAGES, "skipped"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
