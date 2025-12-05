from __future__ import annotations

from celery import Celery

from app.core.config import settings


def create_celery_app() -> Celery:
    """Create and configure the Celery application instance."""
    app = Celery(
        "netpulse",
        broker=settings.celery_broker_url,
        backend=settings.celery_result_backend,
    )

    # Ensure tasks are autodiscovered from the app.tasks module
    app.conf.update(
        task_default_queue="default",
        task_time_limit=300,
        worker_max_tasks_per_child=100,
        beat_schedule={
            # Pulse: monitor latency every 10 seconds
            "monitor-latency-every-10s": {
                "task": "app.tasks.monitor_latency_task",
                "schedule": 10.0,
            },
            # Eye: passive ARP discovery every 60 seconds
            "passive-arp-discovery-every-60s": {
                "task": "app.tasks.passive_arp_discovery_task",
                "schedule": 60.0,
            },
            # Alerts: scan for new high/critical vulnerabilities every 5 minutes
            "vulnerability-alerts-every-5m": {
                "task": "app.tasks.vulnerability_alert_task",
                "schedule": 300.0,
            },
        },
    )

    return app


celery_app: Celery = create_celery_app()