# Vulture whitelist — intentional false-positives for the NetPulse Python codebase.
#
# WHY: Vulture performs static dead-code analysis. Several live patterns are
# invisible to it: FastAPI dependency callables are only ever called by the
# framework's DI container (never directly), and Celery task functions are
# only invoked via .delay()/.apply_async() from worker internals. Without
# entries here, vulture would report them as unused and fail CI.
#
# Add an entry for every function/class that vulture flags as unused but is
# genuinely alive at runtime. Reference the file and line in a comment so
# the entry can be removed if the code it covers is ever deleted.

from app.api.deps import require_role  # noqa: F401 — used as Depends(require_role(...))
from app.api.deps import require_admin  # noqa: F401 — used as Depends(require_admin)
from app.api.deps import db_session  # noqa: F401 — used as Depends(db_session)
from app.api.deps import get_current_user  # noqa: F401 — used as Depends(get_current_user)
