"""Abstract contracts for every swappable pipeline stage.

Concrete implementations live under sibling packages (camera/, detection/,
quality/, embedding/, liveness/, similarity/, storage/, policy/,
rate_limiting/) and depend on these interfaces, never the other way around.
"""
