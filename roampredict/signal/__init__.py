"""Signal processing: spike rejection, smoothing and trend estimation.

Always import as ``roampredict.signal`` (never run files in this folder
directly), so this package cannot be confused with Python's own ``signal``.
"""

from roampredict.signal.filter import FilterConfig, FilteredSample, SignalFilter
from roampredict.signal.trend import (
    SlidingRegression,
    TrendConfig,
    TrendEstimate,
    linear_fit,
    time_to_threshold,
)

__all__ = [
    "FilterConfig",
    "FilteredSample",
    "SignalFilter",
    "SlidingRegression",
    "TrendConfig",
    "TrendEstimate",
    "linear_fit",
    "time_to_threshold",
]
