"""Shared limits for operator-selected assessment parallelism."""

DEFAULT_MAX_PARALLEL = 2
MAX_PARALLEL = 16


def validate_max_parallel(value: int) -> int:
    if type(value) is not int or not 1 <= value <= MAX_PARALLEL:
        raise ValueError(f"max_parallel must be an integer between 1 and {MAX_PARALLEL}")
    return value
