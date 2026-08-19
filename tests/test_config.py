from pathlib import Path

from rangeforge.config import ConfigLoader


def test_missing_config_uses_defaults_without_writing(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    config = ConfigLoader(path).load()
    assert config.runtime.default == "auto"
    assert not path.exists()


def test_configured_image_cache_path(tmp_path: Path) -> None:
    path = tmp_path / "config.yaml"
    cache = tmp_path / "custom-cache"
    path.write_text(f"images:\n  cache_dir: {cache}\n", encoding="utf-8")
    config = ConfigLoader(path).load()
    assert config.images.cache_dir == cache
    assert not cache.exists()

