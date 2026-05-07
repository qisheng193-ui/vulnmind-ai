from __future__ import annotations

import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DIST_DIR = ROOT / "dist"


def build_archives() -> list[Path]:
    DIST_DIR.mkdir(exist_ok=True)

    project_archive = shutil.make_archive(
        str(DIST_DIR / "vulnmind_agent_project"),
        "zip",
        root_dir=ROOT,
        base_dir=".",
    )

    workspace_root = ROOT / "xiaomi_submission" / "workspace_template"
    workspace_archive = shutil.make_archive(
        str(DIST_DIR / "xiaomi_agent_workspace_template"),
        "zip",
        root_dir=workspace_root,
        base_dir=".",
    )

    return [Path(project_archive), Path(workspace_archive)]


def main() -> int:
    archives = build_archives()
    print("[VulnMind AI] Submission artifacts:")
    for archive in archives:
        print(f" - {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
