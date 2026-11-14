"""NEAR Rust contract analyzer: function extraction (tree-sitter), NEAR-specific detectors, model features."""
from .detectors import detect
from .features import features
from .rust_parse import extract_functions

__all__ = ["extract_functions", "detect", "features"]
