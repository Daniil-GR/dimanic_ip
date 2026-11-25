"""Configurable, non-overlapping monitor timing; caller serializes access."""
import math

INTERVAL = 120
MIN_INTERVAL = 60
MAX_INTERVAL = 86400

def validate_interval(value):
    if type(value) is not int or not MIN_INTERVAL <= value <= MAX_INTERVAL or value % 60:
        raise ValueError('Интервал должен быть целым числом от 1 до 1440 минут.')
    return value

class Monitor:
    def __init__(self):
        self.enabled = False
        self.generation = 0
        self.target = None
        self.timeout = 10
        self.next_due = None
        self.message = ''
        self.committing = False
        self.interval = INTERVAL
        self.auto_cleanup = False
        self.allow_empty = False

    def start(self, target, timeout, now, interval=None, auto_cleanup=False, allow_empty=False):
        if self.enabled or self.committing:
            raise ValueError('Мониторинг уже запущен или завершается удаление.')
        interval = validate_interval(self.interval if interval is None else interval)
        if type(auto_cleanup) is not bool:
            raise ValueError('Некорректный режим автоудаления.')
        if type(allow_empty) is not bool or (allow_empty and not auto_cleanup):
            raise ValueError('Полная очистка требует автоудаления.')
        self.interval = interval
        self.auto_cleanup = auto_cleanup
        self.allow_empty = allow_empty
        self.generation += 1
        self.enabled = True
        self.target = target
        self.timeout = timeout
        self.next_due = now
        self.message = ''

    def set_interval(self, interval, now):
        interval = validate_interval(interval)
        if interval != self.interval:
            self.interval = interval
            if self.enabled:
                self.next_due = now + interval

    def stop(self, message='Мониторинг остановлен.'):
        self.enabled = False
        self.generation += 1
        self.next_due = None
        self.auto_cleanup = False
        self.allow_empty = False
        self.message = message

    def due(self, now, busy):
        return self.enabled and not busy and self.next_due is not None and now >= self.next_due

    def matches(self, generation, target):
        return self.enabled and self.generation == generation and self.target == target

    def started(self, now):
        self.next_due = now + self.interval
        self.message = ''

    def public(self, now):
        return {'enabled': self.enabled, 'host': self.target[0] if self.target else '',
                'port': self.target[1] if self.target else None, 'interval': self.interval, 'auto_cleanup': self.auto_cleanup, 'allow_empty': self.allow_empty,
                'seconds': max(0, math.ceil(self.next_due-now)) if self.enabled and self.next_due is not None else None,
                'message': self.message, 'committing': self.committing}
