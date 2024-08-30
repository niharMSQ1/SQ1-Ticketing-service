from django.apps import AppConfig


class FicektingOperationsApp(AppConfig):
    name = 'ticektingOperationsApp'

    def ready(self):
        from .scheduler import start_scheduler
        start_scheduler()
