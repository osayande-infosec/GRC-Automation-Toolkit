"""
Celery configuration and task definitions for background jobs.
"""
from celery import Celery
from app.core.config import settings

celery = Celery(
    "compliance_platform",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
    include=[
        "app.workers.tasks.integrations",
        "app.workers.tasks.compliance",
        "app.workers.tasks.vulnerabilities",
    ]
)

# Celery configuration
celery.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_time_limit=3600,  # 1 hour max per task
    worker_prefetch_multiplier=1,
    task_acks_late=True,
)

# Beat schedule for periodic tasks
celery.conf.beat_schedule = {
    # Sync AWS assets every 6 hours
    "sync-aws-assets": {
        "task": "app.workers.tasks.integrations.sync_aws_assets",
        "schedule": 21600.0,  # 6 hours in seconds
    },
    # Check vulnerability SLAs every hour
    "check-vulnerability-slas": {
        "task": "app.workers.tasks.vulnerabilities.check_sla_breaches",
        "schedule": 3600.0,  # 1 hour
    },
    # Daily compliance evidence collection
    "collect-compliance-evidence": {
        "task": "app.workers.tasks.compliance.collect_evidence",
        "schedule": 86400.0,  # 24 hours
    },
    # Weekly compliance report generation
    "generate-weekly-report": {
        "task": "app.workers.tasks.compliance.generate_weekly_report",
        "schedule": 604800.0,  # 7 days
    },
}
