"""IGA-Guard API Gunicorn 生产配置。"""
import multiprocessing
import os

bind = f"0.0.0.0:{os.environ.get('IGA_API_PORT', '5000')}"
workers = int(os.environ.get("IGA_GUNICORN_WORKERS", max(2, multiprocessing.cpu_count() // 2)))
worker_class = "sync"
timeout = 120
keepalive = 5
accesslog = "-"
errorlog = "-"
loglevel = os.environ.get("IGA_LOG_LEVEL", "info")
preload_app = True
graceful_timeout = 30
