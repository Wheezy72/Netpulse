from __future__ import annotations

from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base


class Network(Base):
    """A physical network this host has been attached to.

    Home networks routinely reuse the same addresses — five houses behind the
    same ``192.168.1.0/24`` with the same gateway IP — so a subnet alone cannot
    tell two of them apart. The identity is therefore the subnet *plus* the
    gateway's MAC address, which is what actually differs when the machine is
    carried somewhere else.

    Devices are scoped to the network they were observed on, so a device at
    ``192.168.1.10`` in one network never overwrites the one in another, and
    the operator can name each network ("Mum's house", "Office VLAN 20") to
    recognise them later.
    """

    __tablename__ = "networks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    # Fingerprint: "<cidr>|<gateway MAC, or ->". Unique so the same network is
    # reused on every later run, while a different one becomes a new row.
    key: Mapped[str] = mapped_column(String(128), unique=True, index=True, nullable=False)
    # Operator-editable label; the generated default is only a suggestion.
    name: Mapped[str] = mapped_column(String(100), nullable=False)
    cidr: Mapped[str] = mapped_column(String(50), nullable=False, default="")
    gateway_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    gateway_mac: Mapped[str | None] = mapped_column(String(32), nullable=True)
    interface: Mapped[str | None] = mapped_column(String(64), nullable=True)

    first_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
    )
    last_seen: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
    )
