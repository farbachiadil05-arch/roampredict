"""A 2-D school floor: four classrooms on the north side, three on the south
side, a hallway in between with a fire door half-way, masonry walls with wooden
doors, five 5 GHz APs.

Coordinates are metres.  The hallway runs along y = 8..12.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["Wall", "AccessPoint", "Room", "FloorPlan", "segments_intersect", "school_floor"]


@dataclass(frozen=True)
class Wall:
    x1: float
    y1: float
    x2: float
    y2: float
    loss_db: float
    material: str


@dataclass(frozen=True)
class AccessPoint:
    name: str
    bssid: str
    x: float
    y: float
    channel: int
    tx_power_dbm: float = 17.0
    ssid: str = "eduroam"

    @property
    def freq_mhz(self) -> int:
        return 5000 + 5 * self.channel


@dataclass(frozen=True)
class Room:
    name: str
    x0: float
    y0: float
    x1: float
    y1: float


def _orient(ax: float, ay: float, bx: float, by: float, cx: float, cy: float) -> float:
    return (bx - ax) * (cy - ay) - (by - ay) * (cx - ax)


def _on_segment(ax: float, ay: float, bx: float, by: float, px: float, py: float) -> bool:
    return min(ax, bx) - 1e-9 <= px <= max(ax, bx) + 1e-9 and min(ay, by) - 1e-9 <= py <= max(ay, by) + 1e-9


def segments_intersect(
    p1: tuple[float, float], p2: tuple[float, float], q1: tuple[float, float], q2: tuple[float, float]
) -> bool:
    """True if segment p1-p2 touches or crosses segment q1-q2."""
    d1 = _orient(*q1, *q2, *p1)
    d2 = _orient(*q1, *q2, *p2)
    d3 = _orient(*p1, *p2, *q1)
    d4 = _orient(*p1, *p2, *q2)
    if ((d1 > 0 > d2) or (d1 < 0 < d2)) and ((d3 > 0 > d4) or (d3 < 0 < d4)):
        return True
    return (
        (d1 == 0 and _on_segment(*q1, *q2, *p1))
        or (d2 == 0 and _on_segment(*q1, *q2, *p2))
        or (d3 == 0 and _on_segment(*p1, *p2, *q1))
        or (d4 == 0 and _on_segment(*p1, *p2, *q2))
    )


@dataclass(frozen=True)
class FloorPlan:
    width: float
    height: float
    walls: tuple[Wall, ...]
    aps: tuple[AccessPoint, ...]
    rooms: tuple[Room, ...]

    def ap(self, bssid: str) -> AccessPoint:
        for ap in self.aps:
            if ap.bssid == bssid:
                return ap
        raise KeyError(bssid)

    def wall_loss(self, ax: float, ay: float, bx: float, by: float) -> float:
        """Total attenuation of all walls/doors crossed by the straight line a-b."""
        loss = 0.0
        for w in self.walls:
            if segments_intersect((ax, ay), (bx, by), (w.x1, w.y1), (w.x2, w.y2)):
                loss += w.loss_db
        return loss


MASONRY_DB = 12.0  # classroom/hallway walls at 5 GHz (assumption)
CONCRETE_DB = 16.0  # walls between classrooms (assumption)
DOOR_DB = 4.0  # closed wooden door (assumption)
FIRE_DOOR_DB = 8.0  # fire door across the hallway (assumption)


def _horizontal_wall(y: float, x0: float, x1: float, doors: list[tuple[float, float]]) -> list[Wall]:
    walls: list[Wall] = []
    cursor = x0
    for d0, d1 in sorted(doors):
        if d0 > cursor:
            walls.append(Wall(cursor, y, d0, y, MASONRY_DB, "masonry"))
        walls.append(Wall(d0, y, d1, y, DOOR_DB, "door"))
        cursor = d1
    if cursor < x1:
        walls.append(Wall(cursor, y, x1, y, MASONRY_DB, "masonry"))
    return walls


def school_floor() -> FloorPlan:
    walls: list[Wall] = []
    # North side of the hallway (classrooms A-D) and south side (E-G).
    walls += _horizontal_wall(12.0, 0.0, 60.0, [(10.5, 12.0), (25.5, 27.0), (40.5, 42.0), (55.5, 57.0)])
    walls += _horizontal_wall(8.0, 0.0, 60.0, [(16.0, 17.5), (36.0, 37.5), (56.0, 57.5)])
    for x in (15.0, 30.0, 45.0):
        walls.append(Wall(x, 12.0, x, 20.0, CONCRETE_DB, "concrete"))
    for x in (20.0, 40.0):
        walls.append(Wall(x, 0.0, x, 8.0, CONCRETE_DB, "concrete"))
    walls.append(Wall(30.0, 8.0, 30.0, 12.0, FIRE_DOOR_DB, "fire door"))

    aps = (
        AccessPoint("AP-A", "02:5e:00:00:00:a1", 6.0, 17.0, channel=36),
        AccessPoint("AP-H1", "02:5e:00:00:00:b1", 22.0, 10.0, channel=149),
        AccessPoint("AP-C", "02:5e:00:00:00:c1", 37.5, 16.5, channel=44),
        AccessPoint("AP-H2", "02:5e:00:00:00:b2", 50.0, 10.0, channel=157),
        AccessPoint("AP-F", "02:5e:00:00:00:f1", 30.0, 4.0, channel=52),
    )
    rooms = (
        Room("A", 0, 12, 15, 20),
        Room("B", 15, 12, 30, 20),
        Room("C", 30, 12, 45, 20),
        Room("D", 45, 12, 60, 20),
        Room("E", 0, 0, 20, 8),
        Room("F", 20, 0, 40, 8),
        Room("G", 40, 0, 60, 8),
        Room("hallway", 0, 8, 60, 12),
    )
    return FloorPlan(width=60.0, height=20.0, walls=tuple(walls), aps=aps, rooms=rooms)
