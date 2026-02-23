from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from fastapi.responses import FileResponse
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, db_session
from app.models.user import User

router = APIRouter()

BACKUP_DIR = Path("data/backups")
BACKUP_DIR.mkdir(parents=True, exist_ok=True)

EXPORTABLE_TABLES = ["devices", "uptime_targets", "network_segments"]
FILENAME_PATTERN = "netpulse_backup_"

TABLE_COLUMN_ALLOWLIST = {
    "devices": {
        "id",
        "hostname",
        "ip_address",
        "mac_address",
        "device_type",
        "os",
        "vendor",
        "zone",
        "is_gateway",
        "last_seen",
        "created_at",
        "updated_at",
    },
    "uptime_targets": {
        "id",
        "name",
        "target",
        "check_type",
        "interval_seconds",
        "is_active",
        "created_at",
        "last_status",
        "last_checked_at",
        "last_latency_ms",
        "consecutive_failures",
    },
    "network_segments": {
        "id",
        "name",
        "cidr",
        "description",
        "vlan_id",
        "is_active",
        "scan_enabled",
        "created_at",
        "updated_at",
    },
}


@router.post("/export")
async def export_db(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
):
    data: Dict[str, Any] = {}
    for table in EXPORTABLE_TABLES:
        try:
            result = await db.execute(text(f"SELECT * FROM {table}"))
            rows = result.mappings().all()
            data[table] = [dict(row) for row in rows]
        except Exception:
            data[table] = []

    filename = f"netpulse_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    filepath = BACKUP_DIR / filename
    with open(filepath, "w") as f:
        json.dump(data, f, default=str, indent=2)

    return FileResponse(filepath, filename=filename, media_type="application/json")


@router.get("/list")
async def list_backups(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    backups = []
    for file in sorted(BACKUP_DIR.glob("netpulse_backup_*.json"), key=lambda f: f.stat().st_mtime, reverse=True):
        stat = file.stat()
        backups.append({
            "filename": file.name,
            "size": stat.st_size,
            "created_at": datetime.fromtimestamp(stat.st_mtime).isoformat(),
        })
    return backups


@router.delete("/{filename}")
async def delete_backup(
    filename: str,
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    if not filename.startswith(FILENAME_PATTERN) or not filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Invalid backup filename format")

    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    filepath = BACKUP_DIR / filename
    if not filepath.exists():
        raise HTTPException(status_code=404, detail="Backup file not found")

    os.remove(filepath)
    return {"status": "deleted", "filename": filename}


@router.post("/restore")
async def restore_db(
    file: UploadFile = File(...),
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not file.filename or not file.filename.endswith(".json"):
        raise HTTPException(status_code=400, detail="Only JSON backup files are accepted")

    try:
        content = await file.read()
        data = json.loads(content)
    except (json.JSONDecodeError, Exception) as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON file: {str(e)}")

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail="Backup file must contain a JSON object")

    counts: Dict[str, int] = {}
    allowed_tables = set(EXPORTABLE_TABLES)

    for table_name, rows in data.items():
        if table_name not in allowed_tables:
            continue
        if not isinstance(rows, list):
            continue

        allowed_columns = TABLE_COLUMN_ALLOWLIST.get(table_name)
        if not allowed_columns:
            continue

        try:
            await db.execute(text(f"DELETE FROM {table_name}"))
        except Exception:
            pass

        inserted = 0
        for row in rows:
            if not isinstance(row, dict):
                continue

            invalid_columns = [k for k in row.keys() if k not in allowed_columns]
            if invalid_columns:
                raise HTTPException(
                    status_code=400,
                    detail=(
                        f"Backup contains invalid column(s) for table '{table_name}': "
                        + ", ".join(invalid_columns)
                    ),
                )

            filtered_row = {k: v for k, v in row.items() if k in allowed_columns}
            if not filtered_row:
                continue

            column_names = list(filtered_row.keys())
            columns = ", ".join(column_names)
            placeholders = ", ".join(f":{k}" for k in column_names)
            try:
                await db.execute(
                    text(f"INSERT INTO {table_name} ({columns}) VALUES ({placeholders})"),
                    filtered_row,
                )
                inserted += 1
            except Exception:
                continue

        counts[table_name] = inserted

    await db.commit()
    return {"status": "restored", "tables": counts}
