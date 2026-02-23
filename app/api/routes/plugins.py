from __future__ import annotations

from typing import Any, Dict, List

from fastapi import APIRouter, Body, Depends

from app.api.deps import get_current_user
from app.plugins import plugin_manager

router = APIRouter()


@router.get("", response_model=List[Dict[str, str]])
async def list_plugins(current_user=Depends(get_current_user)):
    return plugin_manager.list_plugins()


@router.post("/{name}/execute")
async def execute_plugin(name: str, context: Dict[str, Any] = Body(default={}), current_user=Depends(get_current_user)):
    result = plugin_manager.execute_plugin(name, context)
    return result


@router.get("/{name}/results")
async def get_plugin_results(name: str, current_user=Depends(get_current_user)):
    plugin = plugin_manager.get_plugin(name)
    if not plugin:
        return {"error": f"Plugin '{name}' not found"}
    return {"plugin": name, "results": plugin_manager.get_results(name)}
