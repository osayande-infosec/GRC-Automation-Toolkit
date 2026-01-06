"""Celery workers package."""
from app.workers.celery import celery

__all__ = ["celery"]
