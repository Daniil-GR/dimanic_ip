"""Persistent retirement of a workspace without changing DNS or global history."""


def marker(root, page_id):
    return root / (page_id + '.deleted')


def retired(root, page_id):
    return marker(root, page_id).exists()


def remove_page(root, pages, page_id, create_page, write):
    """Caller holds the workspace registry lock and the page request lock."""
    module = pages.get(page_id)
    if module is None:
        raise ValueError('Страница уже удалена.')
    with module.LOCK:
        if module.MONITOR.enabled:
            module.MONITOR.stop('Мониторинг остановлен для удаления страницы.')
        if module.STATE['phase'] in module.ACTIVE_PHASES or module.MONITOR.committing or module.PAUSE_COMMIT:
            raise ValueError('Мониторинг остановлен. Дождитесь завершения текущей операции и повторите удаление.')
        if len(pages) == 1:
            create_page()
        next_id = next(key for key in pages if key != page_id)
        # Persist retirement before removing it from the registry. Reports remain
        # on disk, and neither shared credentials nor global history are touched.
        write(marker(root, page_id), {'deleted': True})
        module.WORKSPACE_CLOSED.set()
        del pages[page_id]
        warning = ''
        try:
            module.LAST_PROXY.unlink(missing_ok=True)
        except OSError:
            warning = 'Страница удалена, но локальный файл MTProto-ссылки не удалось очистить.'
        module.LAST = None
        return {'deleted': page_id, 'next': next_id, 'warning': warning}
