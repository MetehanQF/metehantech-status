"""Gunicorn entry point with exactly one in-process metrics collector."""

from app import app, get_status
from alerts import start_camera_monitor
from camera import get_camera_status, start_canary_collector
from history import start_collector


start_collector(get_status)
start_camera_monitor(get_camera_status)
start_canary_collector()
