"""Contextual command registry and global entry points.

Based on OpenCode's command-palette.tsx / config/keybind.ts at commit
3865c696efc97f30a34ea55b1d0ea4c26d939ecd: reachable commands, descriptions,
search, one modal dispatcher, and Ctrl+P for the command list.
"""
from __future__ import annotations

from dataclasses import replace

from . import dialogs, navigation, state
from .actions import Action, group_actions, key_of

DESCRIPTIONS = {
    "Аудит": "Открыть сведения о выбранной сети и план проверки.",
    "Отчёт": "Открыть сведения о выбранной сети и план проверки.",
    "Ключи": "Посмотреть сохранённые профили и ключи Windows.",
    "Настройка": "Источник данных, метод, словарь и лимит времени.",
    "Параметры": "Изменить источник данных и параметры подбора.",
    "Файл захвата": "Выбрать готовый файл захвата .pcapng и сразу проверить его.",
    "Обновить": "Повторно прочитать список для этого экрана.",
    "Начать подбор": (
        "Запустить проверку выбранной сети: сначала ключ из истории "
        "подключений Windows, затем захват и подбор."
    ),
    "Захват адаптером": "Записать данные адаптером без подбора пароля.",
    "Проверить компоненты": "Обновить доступность компонентов.",
    "Файл": "Выбрать файл для текущего поля: захват, словарь или правила.",
    "Установить компоненты": "Недостающие инструменты и словари.",
    "Справка": "Методы проверки, источники данных и ограничения.",
    "Назад": "Вернуться на предыдущий экран, сохранив выбор.",
    "Закрыть": "Закрыть справку и вернуться на предыдущий экран.",
    "К списку сетей": "Открыть главный экран.",
    "Повторить подбор": "Те же параметры запуска.",
    "Остановить": "Остановить текущий процесс и дождаться результата.",
    "Выход": "Завершить приложение.",
    "Открыть": "Открыть выбранную папку или выбрать файл.",
    "Вверх": "Перейти в родительскую папку.",
    "Выбрать": "Использовать выбранную точку доступа из файла.",
    "Страница +": "Следующая страница справки.",
    "Страница −": "Предыдущая страница справки.",
}


def confirm_exit() -> None:
    from .controller import quit_app

    dialogs.open_select("Завершить приложение?", [
        Action("Продолжить работу", lambda: None),
        Action("Завершить приложение", quit_app, danger=True),
    ], searchable=False)


def confirm_stop() -> None:
    from .controller import cancel_attack

    if state.cancelled.peek():
        return
    source = state.run_source.peek()
    capture = source == "board" or state.capture_left.peek() is not None
    operation = "ожидание" if source == "board" else "захват" if capture else "подбор"
    title = f"Остановить {operation}?"
    dialogs.open_select(title, [
        Action(f"Продолжить {operation}", lambda: None),
        Action(f"Остановить {operation}", cancel_attack, danger=True),
    ], searchable=False)


def open_parameters() -> None:
    from . import forms

    phase = state.phase.peek()
    network = state.selected_network()
    if phase == "audit":
        network = state.audit_network.peek()
    elif phase == "result" and state.result.peek() is not None:
        network = state.result.peek().network
    elif phase == "saved":
        from .screens.saved import _selected_profile
        from ..models import Network

        profile = _selected_profile()
        network = Network(ssid=profile.name, bssid="", auth=profile.auth) if profile else None
    forms.open_form(network)


def show_last_result() -> None:
    latest = state.last_result.peek() or state.result.peek()
    if latest is not None:
        navigation.push("result")
        state.result.set(latest)
        state.log_scroll.set(0)


def saved_action() -> tuple[Action, ...]:
    """The entry into the connection history, or nothing when it is off.

    A shortcut that is switched off must not stay on the menu as a row that
    presses and says no: the user should not have to remember why half their
    networks are not in the list.
    """
    from .. import profiles as profiles_mod
    from . import controller

    if not profiles_mod.HISTORY_ENABLED:
        return ()
    return (Action("Ключи", controller.go_to_saved,
                   description=DESCRIPTIONS["Ключи"], category="Переходы"),)


def available() -> list[Action]:
    from . import board_captures, controller, forms
    from .screens import audit, crack, crack_form, result, saved, scan

    phase = state.phase.peek()
    providers = {
        "scan": scan.scan_actions,
        "audit": lambda: audit.audit_actions(
            audit._blocker(state.audit_network.peek(), state.readiness.peek())
            if state.audit_network.peek() is not None else "Нет выбранной сети"),
        "saved": saved.saved_actions,
        "crack_form": lambda: crack_form.form_actions(
            forms.start_problem() or state.form_error.peek()),
        "file_picker": crack_form.picker_actions,
        "method_help": crack_form.help_actions,
        "capture_targets": lambda: crack_form.target_actions(len(state.capture_targets.peek())),
        "crack": lambda: crack.crack_actions(not state.cancelled.peek()),
        "result": lambda: result.result_actions(state.result.peek() is not None),
    }
    local = providers.get(phase, scan.scan_actions)()
    items = [
        replace(item,
                run=(confirm_exit if item.label == "Выход" else
                     confirm_stop if item.label in ("Остановить", "Остановить ожидание") else item.run),
                description=item.description or DESCRIPTIONS.get(item.label, ""),
                category=item.category or "Основное")
        for item in local
    ]
    if (phase not in ("crack", "file_picker", "capture_targets", "method_help")
            and state.install_state.peek() != "working"):
        global_items = [
            Action("Захваты с платы", board_captures.browse,
                   enabled=not controller._board_busy and (bool(state.board.peek()) or controller.board_is_plugged()),
                   description="Сохранённые файлы со стика и найденные в них пары EAPOL.", category="Источники"),
            Action("К списку сетей", controller.go_to_scan,
                   description="Главный экран со всеми найденными сетями.", category="Переходы"),
            *saved_action(),
            Action("Параметры", open_parameters,
                   description=DESCRIPTIONS["Параметры"], category="Настройки"),
            Action("Справка", forms.open_help,
                   description=DESCRIPTIONS["Справка"], category="Сведения"),
        ]
        latest = state.last_result.peek() or state.result.peek()
        if latest is not None and (phase != "result" or latest is not state.result.peek()):
            global_items.append(Action(
                "Последний результат", show_last_result,
                description="Показать последний завершённый результат.", category="Переходы"))
        labels = {item.label for item in items}
        items.extend(item for item in global_items if item.label not in labels
                     and not (phase == "scan" and item.label == "К списку сетей")
                     and not (phase == "crack_form" and item.label == "Параметры")
                     and not (item.label == "К списку сетей" and "К списку сетей" in labels)
                     and not (phase == "saved" and item.label == "Ключи")
                     and not (phase == "method_help" and item.label == "Справка"))
    if not any(item.label == "Выход" for item in items):
        items.append(Action("Выход", confirm_exit, danger=True,
                            description=DESCRIPTIONS["Выход"], category="Приложение"))
    return group_actions(items)


def open_menu() -> None:
    dialogs.open_select(f"Команды · {navigation.LABELS.get(state.phase.peek(), '')}",
                        available(), palette=True)


def handle_global(event) -> bool:
    key = key_of(event)
    ctrl = bool(getattr(event, "ctrl", False))
    # A slash in a path, mask or search is ordinary text.
    if key == "/" and state.phase.peek() == "scan":
        from .screens.scan import _choices, focus_search
        from .controls import peek_focus
        if peek_focus("scan", _choices(), default="list") != "search":
            event.stop_propagation()
            focus_search()
            return True
        return False
    slash = key == "/" and state.phase.peek() not in ("crack_form", "file_picker")
    if key in ("f1", "menu") or (ctrl and key == "p") or slash:
        event.stop_propagation()
        open_menu()
        return True
    if ctrl and key == "c":
        event.stop_propagation()
        confirm_stop() if state.phase.peek() == "crack" else confirm_exit()
        return True
    return False
