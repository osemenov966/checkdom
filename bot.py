
import os
import re
import sqlite3
import asyncio
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple

import aiohttp
from aiogram import Bot, Dispatcher, types
from aiogram.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
    Message,
    CallbackQuery,
)
from aiogram.utils import executor
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger

# ==========================
# Налаштування
# ==========================

# ❗ ВАЖЛИВО: встанови змінну оточення BOT_TOKEN на Railway / сервері
BOT_TOKEN = os.getenv("BOT_TOKEN", "").strip()
DB_PATH = os.getenv("DB_PATH", "bot_data.db")

if not BOT_TOKEN:
    raise RuntimeError(
        "Не задано BOT_TOKEN. "
        "Додай змінну оточення BOT_TOKEN на хостингу з токеном свого Telegram-бота."
    )

# ==========================
# Допоміжні структури
# ==========================

CATEGORY_UA = {
    "harmless": "безпечний",
    "undetected": "загроз не виявлено",
    "suspicious": "підозрілий",
    "phishing": "фішинговий",
    "malicious": "шкідливий",
    "malware": "шкідливий (malware)",
    "timeout": "таймаут перевірки",
    "unrated": "без рейтингу",
}

SAFE_CATEGORIES = {"harmless", "undetected", "timeout", "unrated"}

RISK_LABELS = {
    "none": ("🟢", "Низький ризик"),
    "low": ("🟢", "Низький ризик"),
    "medium": ("🟡", "Середній ризик"),
    "high": ("🔴", "Високий ризик"),
}


class UserState:
    NONE = "none"
    ENTER_API = "enter_api"
    ONE_TIME_DOMAINS = "one_time_domains"
    CREATE_LIST_NAME = "create_list_name"
    ADD_LIST_DOMAINS = "add_list_domains"
    OVERWRITE_LIST_DOMAINS = "overwrite_list_domains"


user_states: Dict[int, str] = {}
state_data: Dict[int, Dict[str, Any]] = {}

# ==========================
# База даних
# ==========================


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            tg_id INTEGER UNIQUE NOT NULL,
            vt_api_key TEXT
        );
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS domain_lists (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            is_daily INTEGER DEFAULT 1,
            is_active INTEGER DEFAULT 1,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        );
    """
    )

    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            list_id INTEGER NOT NULL,
            domain TEXT NOT NULL,
            FOREIGN KEY (list_id) REFERENCES domain_lists (id) ON DELETE CASCADE
        );
    """
    )

    conn.commit()
    conn.close()


def get_or_create_user(tg_id: int) -> sqlite3.Row:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE tg_id = ?", (tg_id,))
    row = cur.fetchone()
    if row:
        conn.close()
        return row

    cur.execute("INSERT INTO users (tg_id) VALUES (?)", (tg_id,))
    conn.commit()
    cur.execute("SELECT * FROM users WHERE tg_id = ?", (tg_id,))
    row = cur.fetchone()
    conn.close()
    return row


def set_user_api_key(tg_id: int, api_key: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE users SET vt_api_key = ? WHERE tg_id = ?", (api_key, tg_id))
    if cur.rowcount == 0:
        cur.execute("INSERT INTO users (tg_id, vt_api_key) VALUES (?, ?)", (tg_id, api_key))
    conn.commit()
    conn.close()


def get_user_api_key(tg_id: int) -> Optional[str]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT vt_api_key FROM users WHERE tg_id = ?", (tg_id,))
    row = cur.fetchone()
    conn.close()
    if row and row["vt_api_key"]:
        return row["vt_api_key"]
    return None


def get_user_id(tg_id: int) -> int:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE tg_id = ?", (tg_id,))
    row = cur.fetchone()
    if row:
        conn.close()
        return row["id"]
    # якщо користувача немає — створюємо
    cur.execute("INSERT INTO users (tg_id) VALUES (?)", (tg_id,))
    conn.commit()
    uid = cur.lastrowid
    conn.close()
    return uid


def create_domain_list(user_id: int, name: str) -> int:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO domain_lists (user_id, name, is_daily, is_active) VALUES (?, ?, 1, 1)",
        (user_id, name),
    )
    conn.commit()
    list_id = cur.lastrowid
    conn.close()
    return list_id


def get_user_lists(user_id: int) -> List[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT dl.id, dl.name, dl.is_daily, dl.is_active, "
        "COUNT(d.id) AS domains_count "
        "FROM domain_lists dl "
        "LEFT JOIN domains d ON d.list_id = dl.id "
        "WHERE dl.user_id = ? "
        "GROUP BY dl.id, dl.name, dl.is_daily, dl.is_active "
        "ORDER BY dl.id ASC",
        (user_id,),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def get_list_by_id(list_id: int) -> Optional[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM domain_lists WHERE id = ?", (list_id,))
    row = cur.fetchone()
    conn.close()
    return row


def set_list_daily_active(list_id: int, active: bool):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "UPDATE domain_lists SET is_active = ? WHERE id = ?",
        (1 if active else 0, list_id),
    )
    conn.commit()
    conn.close()


def delete_list(list_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM domains WHERE list_id = ?", (list_id,))
    cur.execute("DELETE FROM domain_lists WHERE id = ?", (list_id,))
    conn.commit()
    conn.close()


def get_list_domains(list_id: int) -> List[str]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT domain FROM domains WHERE list_id = ? ORDER BY id ASC", (list_id,))
    rows = cur.fetchall()
    conn.close()
    return [r["domain"] for r in rows]


def clear_list_domains(list_id: int):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("DELETE FROM domains WHERE list_id = ?", (list_id,))
    conn.commit()
    conn.close()


def add_domains_to_list(list_id: int, domains: List[str]):
    if not domains:
        return
    conn = get_db_connection()
    cur = conn.cursor()
    existing = set(get_list_domains(list_id))
    for d in domains:
        if d not in existing:
            cur.execute("INSERT INTO domains (list_id, domain) VALUES (?, ?)", (list_id, d))
    conn.commit()
    conn.close()


def get_all_active_daily_lists() -> List[sqlite3.Row]:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        "SELECT dl.id, dl.name, dl.user_id, u.tg_id "
        "FROM domain_lists dl "
        "JOIN users u ON u.id = dl.user_id "
        "WHERE dl.is_daily = 1 AND dl.is_active = 1"
    )
    rows = cur.fetchall()
    conn.close()
    return rows


# ==========================
# Робота з доменами / VirusTotal
# ==========================


DOMAIN_REGEX = re.compile(
    r"(?:(?:https?://)?(?:www\.)?)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})",
    re.IGNORECASE,
)


def extract_domains_from_text(text: str) -> List[str]:
    matches = DOMAIN_REGEX.findall(text)
    normalized = []
    for m in matches:
        d = m.strip().lower()
        # прибираємо крапки/слеші в кінці
        d = d.rstrip("/.")
        if d and d not in normalized:
            normalized.append(d)
    return normalized


async def fetch_domain_vt(session: aiohttp.ClientSession, api_key: str, domain: str) -> Dict[str, Any]:
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        async with session.get(url, headers=headers, timeout=30) as resp:
            if resp.status == 200:
                data = await resp.json()
                return {"ok": True, "data": data}
            else:
                return {"ok": False, "error": f"http_{resp.status}"}
    except asyncio.TimeoutError:
        return {"ok": False, "error": "timeout"}
    except Exception as e:
        return {"ok": False, "error": f"exception_{type(e).__name__}"}


def analyze_vt_domain(domain: str, vt_response: Dict[str, Any]) -> Dict[str, Any]:
    """
    Повертає структуру:
    {
        "domain": str,
        "error": Optional[str],
        "n_problems": int,
        "n_serious": int,
        "problems": [{"engine":..., "category":..., "label":...}, ...],
        "risk_level": "none"/"low"/"medium"/"high",
        "risk_emoji": str,
        "risk_label": str
    }
    """
    if not vt_response.get("ok"):
        return {
            "domain": domain,
            "error": vt_response.get("error", "unknown_error"),
            "n_problems": 0,
            "n_serious": 0,
            "problems": [],
            "risk_level": "none",
            "risk_emoji": "⚪️",
            "risk_label": "Невідомо",
        }

    data = vt_response.get("data") or {}
    attributes = data.get("data", {}).get("attributes", {})
    last_results = attributes.get("last_analysis_results", {}) or {}
    problems = []

    n_problems = 0
    n_serious = 0

    for engine_name, result in last_results.items():
        category = (result or {}).get("category") or "unrated"
        if category not in SAFE_CATEGORIES:
            n_problems += 1
            if category in {"phishing", "malware", "malicious"}:
                n_serious += 1
            label = CATEGORY_UA.get(category, "невідомий статус")
            problems.append(
                {
                    "engine": engine_name,
                    "category": category,
                    "label": label,
                }
            )

    # Визначаємо рівень ризику
    if n_problems == 0:
        risk_level = "none"
    else:
        only_suspicious = all(p["category"] == "suspicious" for p in problems)
        if only_suspicious and n_problems <= 2:
            risk_level = "low"
        elif n_serious >= 3 or n_problems >= 5:
            risk_level = "high"
        else:
            risk_level = "medium"

    emoji, label = RISK_LABELS.get(risk_level, ("⚪️", "Невідомо"))

    return {
        "domain": domain,
        "error": None,
        "n_problems": n_problems,
        "n_serious": n_serious,
        "problems": problems,
        "risk_level": risk_level,
        "risk_emoji": emoji,
        "risk_label": label,
    }


def format_problems_count_ua(n: int) -> str:
    if n == 0:
        return "0 проблемних детекторів загроз"
    if n == 1:
        return "1 проблемний детектор загроз"
    if 2 <= n <= 4:
        return f"{n} проблемні детектори загроз"
    return f"{n} проблемних детекторів загроз"


def build_vt_link(domain: str) -> str:
    url = f"https://www.virustotal.com/gui/domain/{domain}"
    return f'<a href="{url}">Перевірка у VirusTotal</a>'


def build_domain_block(result: Dict[str, Any]) -> str:
    domain = result["domain"]
    if result.get("error"):
        return f"{domain} — ❌ Помилка: {result['error']}"

    risk_emoji = result["risk_emoji"]
    risk_label = result["risk_label"]
    n_prob = result["n_problems"]

    header = f"{domain} — {risk_emoji} {risk_label}"
    status_line = f"Статус: {format_problems_count_ua(n_prob)}"

    if n_prob == 0:
        return f"{header}\n{status_line}\n{build_vt_link(domain)}"

    detectors_lines = []
    for p in result["problems"]:
        detectors_lines.append(f"- {p['engine']} — {p['category']} ({p['label']})")

    detectors_block = "Детектори:\n" + "\n".join(detectors_lines)
    vt_link = build_vt_link(domain)
    return f"{header}\n{status_line}\n{detectors_block}\n\n{vt_link}"


def split_messages(blocks: List[str], limit: int = 3500) -> List[str]:
    messages = []
    current = ""
    for block in blocks:
        block = block.strip()
        if not block:
            continue
        if len(current) + len(block) + 2 > limit:
            if current:
                messages.append(current.strip())
            current = block + "\n\n"
        else:
            current += block + "\n\n"
    if current.strip():
        messages.append(current.strip())
    return messages


async def scan_domains(
    domains: List[str],
    api_key: str,
    progress_message: Optional[Message] = None,
) -> List[Dict[str, Any]]:
    results: List[Dict[str, Any]] = []
    total = len(domains)
    if total == 0:
        return results

    async with aiohttp.ClientSession() as session:
        last_edit = 0.0
        for idx, domain in enumerate(domains, start=1):
            vt_resp = await fetch_domain_vt(session, api_key, domain)
            analyzed = analyze_vt_domain(domain, vt_resp)
            results.append(analyzed)

            # оновлюємо прогрес раз на кілька секунд
            if progress_message:
                now = asyncio.get_event_loop().time()
                if now - last_edit >= 5.0 or idx == total:
                    try:
                        await progress_message.edit_text(
                            f"Перевірка виконується...\n{idx} / {total} доменів оброблено"
                        )
                    except Exception:
                        pass
                    last_edit = now

            # невелика пауза, щоб не упертися в ліміти
            await asyncio.sleep(0.3)

    return results


def summarize_results(results: List[Dict[str, Any]]) -> Dict[str, int]:
    summary = {
        "total": len(results),
        "normal": 0,
        "one_problem": 0,
        "many_problems": 0,
        "errors": 0,
    }
    for r in results:
        if r.get("error"):
            summary["errors"] += 1
        else:
            n = r["n_problems"]
            if n == 0:
                summary["normal"] += 1
            elif n == 1:
                summary["one_problem"] += 1
            else:
                summary["many_problems"] += 1
    return summary


def build_summary_text(summary: Dict[str, int]) -> str:
    total = summary["total"]
    normal = summary["normal"]
    one_problem = summary["one_problem"]
    many = summary["many_problems"]
    errors = summary["errors"]

    lines = [f"Готово.\nЗагалом доменів: {total}"]
    lines.append(f"🟢 Без проблем: {normal}")
    lines.append(f"🟡 З 1 проблемним детектором: {one_problem}")
    lines.append(f"🔴 З 2+ проблемними детекторами: {many}")
    if errors:
        lines.append(f"❌ З помилками при перевірці: {errors}")
    return "\n".join(lines)


RISK_INFO_TEXT = """
🟢 Низький ризик
— Немає детектів або лише 1–2 «suspicious».
— Можна тестувати домен, але бажано слідкувати за подальшими детектами.

🟡 Середній ризик
— Є декілька підозрілих / фішингових / шкідливих детектів.
— Рекомендовано обмежити трафік, використовувати з обережністю.

🔴 Високий ризик
— Багато «phishing» / «malware» / «malicious» детектів.
— Небезпечно лити трафік: високий ризик блокувань, скарг та втрати конверсій.
""".strip()

# ==========================
# Telegram-бот
# ==========================

bot = Bot(token=BOT_TOKEN, parse_mode="HTML")
dp = Dispatcher(bot)
scheduler = AsyncIOScheduler()


def set_state(user_id: int, state: str, data: Optional[Dict[str, Any]] = None):
    user_states[user_id] = state
    state_data[user_id] = data or {}


def get_state(user_id: int) -> str:
    return user_states.get(user_id, UserState.NONE)


def get_state_data(user_id: int) -> Dict[str, Any]:
    return state_data.get(user_id, {})


def clear_state(user_id: int):
    user_states[user_id] = UserState.NONE
    state_data[user_id] = {}


def main_menu_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("✅ Разова перевірка доменів", callback_data="one_time"))
    kb.add(InlineKeyboardButton("📅 Щоденна перевірка списків", callback_data="daily"))
    kb.add(InlineKeyboardButton("🔐 Мій API-ключ", callback_data="api_menu"))
    kb.add(InlineKeyboardButton("ℹ️ Допомога та ліміти", callback_data="help"))
    return kb


def api_menu_kb(has_key: bool) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("🔄 Змінити API-ключ", callback_data="api_change"))
    if has_key:
        kb.add(InlineKeyboardButton("🗑 Видалити API-ключ", callback_data="api_delete"))
    kb.add(InlineKeyboardButton("⬅️ Назад", callback_data="back_main"))
    return kb


def daily_menu_kb(has_lists: bool) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("➕ Створити новий список", callback_data="create_list"))
    if has_lists:
        kb.add(InlineKeyboardButton("🗂 Мої списки доменів", callback_data="my_lists"))
    kb.add(InlineKeyboardButton("⬅️ Назад", callback_data="back_main"))
    return kb


def list_actions_kb(list_id: int, is_active: bool) -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("👁 Переглянути домени", callback_data=f"list_view:{list_id}"))
    kb.add(InlineKeyboardButton("➕ Додати домени", callback_data=f"list_add:{list_id}"))
    kb.add(InlineKeyboardButton("🧹 Перезаписати список", callback_data=f"list_overwrite:{list_id}"))
    toggle_text = "🔔 Вимкнути щоденну перевірку" if is_active else "🔔 Увімкнути щоденну перевірку"
    kb.add(InlineKeyboardButton(toggle_text, callback_data=f"list_toggle:{list_id}"))
    kb.add(InlineKeyboardButton("🗑 Видалити список", callback_data=f"list_delete:{list_id}"))
    kb.add(InlineKeyboardButton("⬅️ Назад", callback_data="my_lists"))
    return kb


def risk_info_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup()
    kb.add(InlineKeyboardButton("ℹ️ Що означають ризики?", callback_data="risk_info"))
    return kb


# ==========================
# Хендлери команд
# ==========================


@dp.message_handler(commands=["start"])
async def cmd_start(message: Message):
    tg_id = message.from_user.id
    get_or_create_user(tg_id)
    api_key = get_user_api_key(tg_id)

    text = (
        "ЙОВ! 👋\n"
        "Це бот для перевірки доменів через VirusTotal.\n\n"
        "1️⃣ Спочатку вкажи свій API-ключ VirusTotal.\n"
        "🔒 Ключ зберігається лише для тебе і використовується тільки для перевірок доменів.\n\n"
        "Далі обери режим:\n"
        "• ✅ Разова перевірка доменів\n"
        "• 📅 Щоденна перевірка списків (щодня о 11:00 за Києвом)\n"
    )

    if api_key:
        masked = api_key[:6] + "..." + api_key[-4:]
        text += f"\nТвій API-ключ вже збережений: <b>{masked}</b>"

    await message.answer(text, reply_markup=main_menu_kb())


@dp.message_handler(commands=["help"])
async def cmd_help(message: Message):
    text = (
        "ℹ️ <b>Допомога</b>\n\n"
        "🔐 <b>API-ключ VirusTotal</b>\n"
        "Кожен користувач бота задає свій API-ключ. Він використовується тільки для перевірок доменів.\n\n"
        "⏱ <b>Ліміти</b>\n"
        "Безкоштовний API VirusTotal має обмеження по кількості запитів за хвилину.\n"
        "Якщо ти відправиш великий список доменів, перевірка може бути повільною або частина запитів може дати помилку rate limit.\n\n"
        "🟢🟡🔴 <b>Рівні ризику</b>:\n"
        + RISK_INFO_TEXT
    )
    await message.answer(text)


# ==========================
# Callback-хендлери (меню)
# ==========================


@dp.callback_query_handler(lambda c: c.data == "back_main")
async def cb_back_main(callback: CallbackQuery):
    await callback.message.edit_text(
        "Головне меню. Обери дію:", reply_markup=main_menu_kb()
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "api_menu")
async def cb_api_menu(callback: CallbackQuery):
    tg_id = callback.from_user.id
    api_key = get_user_api_key(tg_id)
    if api_key:
        masked = api_key[:6] + "..." + api_key[-4:]
        text = f"Твій поточний API-ключ VirusTotal:\n<b>{masked}</b>\n\nЩо зробити?"
        has_key = True
    else:
        text = "API-ключ VirusTotal ще не заданий. Можеш додати його зараз."
        has_key = False

    await callback.message.edit_text(text, reply_markup=api_menu_kb(has_key))
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "api_change")
async def cb_api_change(callback: CallbackQuery):
    tg_id = callback.from_user.id
    set_state(tg_id, UserState.ENTER_API, {})
    await callback.message.edit_text(
        "Надішли, будь ласка, свій API-ключ VirusTotal одним повідомленням.\n\n"
        "👉 Не передавай цей ключ стороннім людям.",
        reply_markup=InlineKeyboardMarkup().add(
            InlineKeyboardButton("⬅️ Назад", callback_data="api_menu")
        ),
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "api_delete")
async def cb_api_delete(callback: CallbackQuery):
    tg_id = callback.from_user.id
    set_user_api_key(tg_id, "")
    await callback.message.edit_text(
        "API-ключ видалено.\n\nМожеш додати новий у меню «🔐 Мій API-ключ».",
        reply_markup=main_menu_kb(),
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "one_time")
async def cb_one_time(callback: CallbackQuery):
    tg_id = callback.from_user.id
    api_key = get_user_api_key(tg_id)
    if not api_key:
        await callback.answer("Спочатку задай свій API-ключ VirusTotal.", show_alert=True)
        return

    set_state(tg_id, UserState.ONE_TIME_DOMAINS, {})
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("⬅️ Назад", callback_data="back_main")
    )
    await callback.message.edit_text(
        "Надішли список доменів одним повідомленням.\n\n"
        "Можна у будь-якому форматі:\n"
        "• по одному в рядок\n"
        "• через пробіл\n"
        "• з http/https, з www або без — я все сам почищу.",
        reply_markup=kb,
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "daily")
async def cb_daily(callback: CallbackQuery):
    tg_id = callback.from_user.id
    api_key = get_user_api_key(tg_id)
    if not api_key:
        await callback.answer("Спочатку задай свій API-ключ VirusTotal.", show_alert=True)
        return

    user_id = get_user_id(tg_id)
    lists = get_user_lists(user_id)
    text = (
        "📅 <b>Щоденна перевірка списків</b>\n\n"
        "Списки перевіряються щодня о 11:00 за Києвом.\n\n"
    )
    if lists:
        text += "Твої списки:\n"
        for idx, lst in enumerate(lists, start=1):
            status = "увімкнено" if lst["is_active"] else "вимкнено"
            text += (
                f"{idx}) «{lst['name']}» — {lst['domains_count']} доменів — "
                f"щоденна перевірка: {status}\n"
            )
    else:
        text += "У тебе ще немає жодного списку."

    await callback.message.edit_text(
        text, reply_markup=daily_menu_kb(has_lists=bool(lists))
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "my_lists")
async def cb_my_lists(callback: CallbackQuery):
    tg_id = callback.from_user.id
    user_id = get_user_id(tg_id)
    lists = get_user_lists(user_id)

    if not lists:
        await callback.message.edit_text(
            "У тебе ще немає списків доменів.\n\n"
            "Створи новий список:",
            reply_markup=daily_menu_kb(False),
        )
        await callback.answer()
        return

    text = "🗂 <b>Твої списки доменів</b>:\n\n"
    kb = InlineKeyboardMarkup()
    for idx, lst in enumerate(lists, start=1):
        status = "увімкнено" if lst["is_active"] else "вимкнено"
        text += (
            f"{idx}) «{lst['name']}» — {lst['domains_count']} доменів — "
            f"щоденна перевірка: {status}\n"
        )
        kb.add(
            InlineKeyboardButton(
                f"Вибрати: «{lst['name']}»",
                callback_data=f"list_select:{lst['id']}",
            )
        )

    kb.add(InlineKeyboardButton("⬅️ Назад", callback_data="daily"))
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "create_list")
async def cb_create_list(callback: CallbackQuery):
    tg_id = callback.from_user.id
    set_state(tg_id, UserState.CREATE_LIST_NAME, {})
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("⬅️ Назад", callback_data="daily")
    )
    await callback.message.edit_text(
        "Введи назву нового списку доменів (наприклад, «PL нутра»):",
        reply_markup=kb,
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data.startswith("list_select:"))
async def cb_list_select(callback: CallbackQuery):
    tg_id = callback.from_user.id
    try:
        list_id = int(callback.data.split(":", 1)[1])
    except Exception:
        await callback.answer("Помилка вибору списку.", show_alert=True)
        return

    lst = get_list_by_id(list_id)
    if not lst:
        await callback.answer("Список не знайдено.", show_alert=True)
        return

    domains = get_list_domains(list_id)
    status = "увімкнено" if lst["is_active"] else "вимкнено"
    text = (
        f"Список: «{lst['name']}»\n"
        f"Кількість доменів: {len(domains)}\n"
        f"Щоденна перевірка: {status}\n\n"
        "Оберіть дію:"
    )

    kb = list_actions_kb(list_id, lst["is_active"] == 1)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data.startswith("list_view:"))
async def cb_list_view(callback: CallbackQuery):
    try:
        list_id = int(callback.data.split(":", 1)[1])
    except Exception:
        await callback.answer("Помилка.", show_alert=True)
        return

    lst = get_list_by_id(list_id)
    if not lst:
        await callback.answer("Список не знайдено.", show_alert=True)
        return

    domains = get_list_domains(list_id)
    if not domains:
        text = f"Список «{lst['name']}» порожній."
    else:
        text = (
            f"Список «{lst['name']}» містить {len(domains)} доменів:\n\n"
            + "\n".join(domains[:200])
        )
        if len(domains) > 200:
            text += "\n\n(Показано перші 200 доменів)"

    kb = list_actions_kb(list_id, lst["is_active"] == 1)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data.startswith("list_add:"))
async def cb_list_add(callback: CallbackQuery):
    tg_id = callback.from_user.id
    try:
        list_id = int(callback.data.split(":", 1)[1])
    except Exception:
        await callback.answer("Помилка.", show_alert=True)
        return

    lst = get_list_by_id(list_id)
    if not lst:
        await callback.answer("Список не знайдено.", show_alert=True)
        return

    set_state(tg_id, UserState.ADD_LIST_DOMAINS, {"list_id": list_id})
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("⬅️ Назад", callback_data=f"list_select:{list_id}")
    )
    await callback.message.edit_text(
        f"Надішли домени, які потрібно <b>додати</b> до списку «{lst['name']}».\n\n"
        "Формат будь-який: по одному в рядок, через пробіл, з http/https тощо.",
        reply_markup=kb,
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data.startswith("list_overwrite:"))
async def cb_list_overwrite(callback: CallbackQuery):
    tg_id = callback.from_user.id
    try:
        list_id = int(callback.data.split(":", 1)[1])
    except Exception:
        await callback.answer("Помилка.", show_alert=True)
        return

    lst = get_list_by_id(list_id)
    if not lst:
        await callback.answer("Список не знайдено.", show_alert=True)
        return

    set_state(tg_id, UserState.OVERWRITE_LIST_DOMAINS, {"list_id": list_id})
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("⬅️ Назад", callback_data=f"list_select:{list_id}")
    )
    await callback.message.edit_text(
        f"Надішли домени для <b>повної заміни</b> списку «{lst['name']}».\n\n"
        "УВАГА: попередні домени будуть видалені.",
        reply_markup=kb,
    )
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data.startswith("list_toggle:"))
async def cb_list_toggle(callback: CallbackQuery):
    try:
        list_id = int(callback.data.split(":", 1)[1])
    except Exception:
        await callback.answer("Помилка.", show_alert=True)
        return

    lst = get_list_by_id(list_id)
    if not lst:
        await callback.answer("Список не знайдено.", show_alert=True)
        return

    new_active = 0 if lst["is_active"] else 1
    set_list_daily_active(list_id, bool(new_active))

    lst = get_list_by_id(list_id)
    domains = get_list_domains(list_id)
    status = "увімкнено" if lst["is_active"] else "вимкнено"
    text = (
        f"Список: «{lst['name']}»\n"
        f"Кількість доменів: {len(domains)}\n"
        f"Щоденна перевірка: {status}\n\n"
        "Оберіть дію:"
    )
    kb = list_actions_kb(list_id, lst["is_active"] == 1)
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer("Налаштування оновлено.")


@dp.callback_query_handler(lambda c: c.data.startswith("list_delete:"))
async def cb_list_delete(callback: CallbackQuery):
    try:
        list_id = int(callback.data.split(":", 1)[1])
    except Exception:
        await callback.answer("Помилка.", show_alert=True)
        return

    lst = get_list_by_id(list_id)
    if not lst:
        await callback.answer("Список не знайдено.", show_alert=True)
        return

    delete_list(list_id)

    tg_id = callback.from_user.id
    user_id = get_user_id(tg_id)
    lists = get_user_lists(user_id)
    if not lists:
        text = "Список видалено. У тебе більше немає списків."
    else:
        text = "Список видалено.\n\nОсь твої оновлені списки:\n"
        for idx, l in enumerate(lists, start=1):
            status = "увімкнено" if l["is_active"] else "вимкнено"
            text += (
                f"{idx}) «{l['name']}» — {l['domains_count']} доменів — "
                f"щоденна перевірка: {status}\n"
            )

    await callback.message.edit_text(
        text, reply_markup=daily_menu_kb(has_lists=bool(lists))
    )
    await callback.answer("Список видалено.")


@dp.callback_query_handler(lambda c: c.data == "help")
async def cb_help(callback: CallbackQuery):
    text = (
        "ℹ️ <b>Допомога та ліміти</b>\n\n"
        "🔐 <b>API-ключ VirusTotal</b>\n"
        "Кожен користувач задає свій ключ. Бот використовує його тільки для перевірок доменів.\n\n"
        "⏱ <b>Ліміти</b>\n"
        "Безкоштовний API VirusTotal обмежує кількість запитів за хвилину. "
        "Якщо список великий, перевірка може бути повільною, а частина доменів може повернути помилки лімітів.\n\n"
        "🟢🟡🔴 <b>Рівні ризику</b>\n"
        + RISK_INFO_TEXT
    )
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("⬅️ Назад", callback_data="back_main")
    )
    await callback.message.edit_text(text, reply_markup=kb)
    await callback.answer()


@dp.callback_query_handler(lambda c: c.data == "risk_info")
async def cb_risk_info(callback: CallbackQuery):
    await callback.message.reply(RISK_INFO_TEXT)
    await callback.answer()


# ==========================
# Обробка текстових повідомлень (стани)
# ==========================


@dp.message_handler(content_types=types.ContentTypes.TEXT)
async def handle_text(message: Message):
    tg_id = message.from_user.id
    text = message.text.strip()
    state = get_state(tg_id)

    # Якщо немає активного стану — показуємо головне меню
    if state == UserState.NONE:
        await message.answer(
            "Не зовсім зрозумів, що ти маєш на увазі 🙂\n"
            "Скористайся кнопками нижче:",
            reply_markup=main_menu_kb(),
        )
        return

    if state == UserState.ENTER_API:
        await handle_enter_api_key(message, text)
    elif state == UserState.ONE_TIME_DOMAINS:
        await handle_one_time_domains(message, text)
    elif state == UserState.CREATE_LIST_NAME:
        await handle_create_list_name(message, text)
    elif state == UserState.ADD_LIST_DOMAINS:
        await handle_add_list_domains(message, text)
    elif state == UserState.OVERWRITE_LIST_DOMAINS:
        await handle_overwrite_list_domains(message, text)
    else:
        await message.answer(
            "Не зовсім зрозумів, що ти маєш на увазі 🙂\n"
            "Скористайся кнопками нижче:",
            reply_markup=main_menu_kb(),
        )


async def handle_enter_api_key(message: Message, text: str):
    tg_id = message.from_user.id
    api_key = text.replace(" ", "")
    if len(api_key) < 20:
        await message.answer(
            "Схоже, це не схоже на API-ключ VirusTotal.\n"
            "Скопіюй ключ повністю та встав одним повідомленням."
        )
        return

    set_user_api_key(tg_id, api_key)
    clear_state(tg_id)
    masked = api_key[:6] + "..." + api_key[-4:]
    await message.answer(
        f"API-ключ збережено: <b>{masked}</b>\n\n"
        "Тепер можеш запускати разову або щоденну перевірку.",
        reply_markup=main_menu_kb(),
    )


async def handle_one_time_domains(message: Message, text: str):
    tg_id = message.from_user.id
    api_key = get_user_api_key(tg_id)
    if not api_key:
        clear_state(tg_id)
        await message.answer(
            "Спочатку задай свій API-ключ VirusTotal у меню «🔐 Мій API-ключ».",
            reply_markup=main_menu_kb(),
        )
        return

    domains = extract_domains_from_text(text)
    if not domains:
        await message.answer(
            "Не знайшов жодного домену у цьому повідомленні.\n"
            "Спробуй ще раз — по одному в рядок або через пробіл."
        )
        return

    clear_state(tg_id)

    await message.answer(f"Знайдено доменів для перевірки: <b>{len(domains)}</b>")

    progress_msg = await message.answer("Починаю перевірку...\n0 / 0 доменів оброблено")

    results = await scan_domains(domains, api_key, progress_message=progress_msg)
    summary = summarize_results(results)
    summary_text = build_summary_text(summary)

    try:
        await progress_msg.edit_text(summary_text, reply_markup=risk_info_kb())
    except Exception:
        await message.answer(summary_text, reply_markup=risk_info_kb())

    blocks = [build_domain_block(r) for r in results]
    msg_parts = split_messages(blocks)

    for part in msg_parts:
        await message.answer(part)


async def handle_create_list_name(message: Message, text: str):
    tg_id = message.from_user.id
    name = text.strip()
    if not name:
        await message.answer("Назва списку не може бути порожньою. Введи іншу назву.")
        return

    user_id = get_user_id(tg_id)
    list_id = create_domain_list(user_id, name)
    clear_state(tg_id)

    set_state(tg_id, UserState.ADD_LIST_DOMAINS, {"list_id": list_id})
    kb = InlineKeyboardMarkup().add(
        InlineKeyboardButton("⬅️ Назад", callback_data=f"list_select:{list_id}")
    )
    await message.answer(
        f"Список «{name}» створено.\n\n"
        "Тепер надішли домени, які потрібно додати до цього списку.",
        reply_markup=kb,
    )


async def handle_add_list_domains(message: Message, text: str):
    tg_id = message.from_user.id
    data = get_state_data(tg_id)
    list_id = data.get("list_id")
    if not list_id:
        clear_state(tg_id)
        await message.answer(
            "Помилка стану. Повертаю тебе в головне меню.", reply_markup=main_menu_kb()
        )
        return

    domains = extract_domains_from_text(text)
    if not domains:
        await message.answer(
            "Не знайшов жодного домену в повідомленні.\n"
            "Спробуй ще раз — по одному в рядок або через пробіл."
        )
        return

    add_domains_to_list(list_id, domains)
    clear_state(tg_id)

    lst = get_list_by_id(list_id)
    count = len(get_list_domains(list_id))

    await message.answer(
        f"До списку «{lst['name']}» додано {len(domains)} доменів.\n"
        f"Загалом у списку тепер: {count} доменів.",
        reply_markup=main_menu_kb(),
    )


async def handle_overwrite_list_domains(message: Message, text: str):
    tg_id = message.from_user.id
    data = get_state_data(tg_id)
    list_id = data.get("list_id")
    if not list_id:
        clear_state(tg_id)
        await message.answer(
            "Помилка стану. Повертаю тебе в головне меню.", reply_markup=main_menu_kb()
        )
        return

    domains = extract_domains_from_text(text)
    if not domains:
        await message.answer(
            "Не знайшов жодного домену в повідомленні.\n"
            "Спробуй ще раз — по одному в рядок або через пробіл."
        )
        return

    clear_list_domains(list_id)
    add_domains_to_list(list_id, domains)
    clear_state(tg_id)

    lst = get_list_by_id(list_id)
    count = len(get_list_domains(list_id))

    await message.answer(
        f"Список «{lst['name']}» повністю перезаписано.\n"
        f"У списку тепер {count} доменів.",
        reply_markup=main_menu_kb(),
    )


# ==========================
# Щоденна перевірка (scheduler)
# ==========================


async def run_daily_checks():
    lists = get_all_active_daily_lists()
    if not lists:
        return

    for lst in lists:
        list_id = lst["id"]
        name = lst["name"]
        tg_id = lst["tg_id"]
        api_key = get_user_api_key(tg_id)
        if not api_key:
            continue

        domains = get_list_domains(list_id)
        if not domains:
            continue

        try:
            # надсилаємо повідомлення про старт
            start_msg = await bot.send_message(
                tg_id,
                f"📅 Щоденна перевірка списку «{name}» розпочата.\n"
                f"Кількість доменів: {len(domains)}",
            )

            results = await scan_domains(domains, api_key, progress_message=start_msg)
            summary = summarize_results(results)
            summary_text = (
                f"📅 Щоденна перевірка списку «{name}» завершена.\n\n"
                + build_summary_text(summary)
            )

            try:
                await start_msg.edit_text(summary_text, reply_markup=risk_info_kb())
            except Exception:
                await bot.send_message(tg_id, summary_text, reply_markup=risk_info_kb())

            blocks = [build_domain_block(r) for r in results]
            msg_parts = split_messages(blocks)
            for part in msg_parts:
                await bot.send_message(tg_id, part)
        except Exception:
            # не валимо бота, якщо в одного юзера помилка
            continue


async def on_startup(dp: Dispatcher):
    init_db()
    # Щоденна перевірка о 11:00 за київським часом
    scheduler.add_job(
        run_daily_checks,
        CronTrigger(hour=11, minute=0, timezone="Europe/Kiev"),
    )
    scheduler.start()


def main():
    init_db()
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)


if __name__ == "__main__":
    main()
