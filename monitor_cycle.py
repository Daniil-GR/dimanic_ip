"""Two-minute, non-overlapping monitor timing; caller serializes access."""
import math

INTERVAL = 120

class Monitor:
    def __init__(self):
        self.enabled = False
        self.generation = 0
        self.target = None
        self.timeout = 10
        self.next_due = None
        self.message = ''
        self.committing = False

    def start(self, target, timeout, now):
        if self.enabled or self.committing:
            raise ValueError('Мониторинг уже запущен или завершается удаление.')
        self.generation += 1
        self.enabled = True
        self.target = target
        self.timeout = timeout
        self.next_due = now
        self.message = ''

    def stop(self, message='Мониторинг остановлен.'):
        self.enabled = False
        self.generation += 1
        self.next_due = None
        self.message = message

    def due(self, now, busy):
        return self.enabled and not busy and self.next_due is not None and now >= self.next_due

    def matches(self, generation, target):
        return self.enabled and self.generation == generation and self.target == target

    def started(self, now):
        self.next_due = now + INTERVAL
        self.message = ''

    def public(self, now):
        return {'enabled': self.enabled, 'host': self.target[0] if self.target else '',
                'port': self.target[1] if self.target else None, 'interval': INTERVAL,
                'seconds': max(0, math.ceil(self.next_due-now)) if self.enabled and self.next_due is not None else None,
                'message': self.message, 'committing': self.committing}
