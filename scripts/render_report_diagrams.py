"""Render project-report Graphviz diagrams to PNG using the installed `dot` binary."""

import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIAGRAMS = ROOT / "docs" / "project-report" / "diagrams"
FIGURES = ROOT / "docs" / "project-report" / "figures"


def main() -> None:
    dot = shutil.which("dot")
    if dot is None:
        raise SystemExit("Graphviz `dot` is required to render project diagrams.")
    FIGURES.mkdir(parents=True, exist_ok=True)
    for source in sorted(DIAGRAMS.glob("*.dot")):
        destination = FIGURES / f"{source.stem}.png"
        subprocess.run(
            [dot, "-Tpng", "-Gdpi=170", str(source), "-o", str(destination)],
            check=True,
        )
        print(destination.relative_to(ROOT))


if __name__ == "__main__":
    main()
