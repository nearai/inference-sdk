"""Validate a shared release and resolve all four SDK package versions."""

import json
import os
import re
import tomllib
from pathlib import Path

LANGUAGES = ("javascript", "python", "rust", "go")
NUMBER = r"(?:0|[1-9][0-9]*)"
SEMVER = re.compile(rf"({NUMBER}\.{NUMBER}\.{NUMBER})(?:-(alpha|beta|rc)\.({NUMBER}))?")


def plan_release(root: Path, version: str) -> dict:
    match = SEMVER.fullmatch(version)
    if match is None:
        raise ValueError(
            "Use X.Y.Z or X.Y.Z-alpha.N, X.Y.Z-beta.N, or X.Y.Z-rc.N, without v."
        )
    base, phase, number = match.groups()
    packages = {}
    for language in LANGUAGES:
        package_version = version
        if language == "python" and phase is not None:
            package_version = (
                base + {"alpha": "a", "beta": "b", "rc": "rc"}[phase] + number
            )

        if language == "javascript":
            path = root / "js/package.json"
            expected = json.loads(path.read_text(encoding="utf-8"))["version"]
        elif language == "python":
            path = root / "py/pyproject.toml"
            expected = tomllib.loads(path.read_text(encoding="utf-8"))["project"][
                "version"
            ]
        elif language == "rust":
            path = root / "rs/Cargo.toml"
            expected = tomllib.loads(path.read_text(encoding="utf-8"))["package"][
                "version"
            ]
        else:
            path = root / "go/go.mod"
            if not re.search(
                r"^module github\.com/nearai/inference-sdk/go$",
                path.read_text(encoding="utf-8"),
                re.MULTILINE,
            ):
                raise ValueError("Unexpected Go module path.")
            if base.split(".", 1)[0] not in {"0", "1"}:
                raise ValueError("Go major versions >=2 require a new /vN module path.")
            expected = package_version

        if package_version != expected:
            raise ValueError(
                f"Requested {language} version {package_version!r} does not match "
                f"{path.relative_to(root)}: {expected!r}."
            )
        packages[language] = {
            "version": package_version,
            "tag": f"go/v{package_version}" if language == "go" else f"v{version}",
        }

    return {
        "release-tag": f"v{version}",
        "packages": packages,
        "prerelease": phase is not None,
        "npm-tag": "next" if phase is not None else "latest",
    }


def main() -> None:
    try:
        plan = plan_release(Path.cwd(), os.environ["RELEASE_VERSION"])
    except ValueError as error:
        raise SystemExit(str(error)) from error

    # Write outputs only after every package has passed validation.
    with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as output:
        for name, value in plan.items():
            encoded = (
                value
                if isinstance(value, str)
                else json.dumps(value, separators=(",", ":"))
            )
            print(f"{name}={encoded}", file=output)
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as summary:
        print(f"GitHub Release: `{plan['release-tag']}`\n", file=summary)
        print("| SDK | Package version | Source tag |", file=summary)
        print("| --- | --- | --- |", file=summary)
        for language, package in plan["packages"].items():
            print(
                f"| {language} | `{package['version']}` | `{package['tag']}` |",
                file=summary,
            )


if __name__ == "__main__":
    main()
