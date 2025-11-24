import os
import re
import logging
import sqlite3
from datetime import datetime
from typing import Dict, Any, List, Tuple

import requests
from aiogram import Bot, Dispatcher, executor, types
from aiogram.types import (
    InlineKeyboardMarkup,
    InlineKeyboardButton,
)
from aiogram.utils.exceptions import MessageNotModified

# ==========================
# НАЛАШТУВАННЯ ТА ЛОГІНГ
# ==========================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("vt_domains_bot")

# --------------------------
# ТЕЛЕГРАМ ТОКЕН БОТА
# --------------------------
# Ти просив сразу вписать токен — делаю:
BOT_TOKEN = "8019651042:AAGMRBGm2-xpFfrJ8vPyg2_v-lvh1m2kDSU"

if not BOT_TOKEN:
    raise RuntimeError(
        "Не задано BOT_TOKEN. Додай змінну оточення BOT_TOKEN на хостингу "
        "або пропиши токен прямо в коді."
    )

bot = Bot(token=BOT_TOKEN, parse_mode=types.ParseMode.MARKDOWN)
dp = Dispatcher(bot)

# ==========================
# БАЗА ДАНИХ (SQLite)
# ==========================

DB_PATH = "vt_domains_bot.db"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Таблиця користувачів і їх API-ключів
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            user_id INTEGER PRIMARY KEY,
            vt_api_key TEXT
        )
        """
    )
    conn.commit()
    conn.close()


def get_db_connection():
    return sqlite3.connect(DB_PATH)


def get_user_api_key(user_id: int) -> str:
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row and row[0] else ""


def set_user_api_key(user_id: int, api_key: str):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO users (user_id, vt_api_key)
        VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET vt_api_key=excluded.vt_api_key
        """,
        (user_id, api_key),
    )
    conn.commit()
    conn.close()


# ==========================
# СТАН КОРИСТУВАЧІВ У ПАМ’ЯТІ
# ==========================

# Користувачі, які зараз вводять API-ключ
WAITING_API_KEY = set()
# Користувачі, які зараз надсилають список доменів на разову перевірку
WAITING_DOMAINS_ONETIME = set()

# ==========================
# ДОВІДКОВІ КОНСТАНТИ
# ==========================

VT_DOMAIN_URL = "https://www.virustotal.com/api/v3/domains/{domain}"
VT_DOMAIN_GUI = "https://www.virustotal.com/gui/domain/{domain}"

PROBLEM_CATEGORIES = {"malicious", "malware", "phishing", "suspicious"}

STATUS_TRANSLATIONS_UA = {
    "malicious": "шкідливий",
    "malware": "шкідливий (malware)",
    "phishing": "фішинговий",
    "suspicious": "підозрілий",
}

# Короткі підказки по ризику
RISK_LABELS = {
    "green": "🟢 Низький ризик",
    "yellow": "🟡 Середній ризик",
    "red": "🔴 Високий ризик",
}


# ==========================
# ДОПОМІЖНІ ФУНКЦІЇ
# ==========================

def is_probable_vt_api_key(text: str) -> bool:
    """
    Дуже груба перевірка, схожа на формат твого ключа VT:
    64 символи hex.
    """
    text = text.strip()
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", text))


def normalize_domain(raw: str) -> str:
    """
    Приводить введений текст до домена:
    - обрізає http/https
    - прибирає www.
    - прибирає шлях / параметри
    - обрізає пробіли
    """
    raw = raw.strip()
    if not raw:
        return ""

    # Прибрати протокол
    raw = re.sub(r"^https?://", "", raw, flags=re.IGNORECASE)

    # Прибрати everything після першого / (шлях)
    raw = raw.split("/")[0]

    # Прибрати порт, якщо є
    raw = raw.split(":")[0]

    # Прибрати www.
    if raw.startswith("www."):
        raw = raw[4:]

    # Дуже груба перевірка домена
    if "." not in raw:
        return ""

    return raw.lower()


def split_domains_from_text(text: str) -> List[str]:
    """
    Отримати список доменів із довільного тексту.
    Допускаємо: розділення пробілами, комами, новими рядками.
    """
    parts = re.split(r"[,\s]+", text)
    domains = []
    seen = set()
    for part in parts:
        d = normalize_domain(part)
        if d and d not in seen:
            seen.add(d)
            domains.append(d)
    return domains


def translate_status(category: str) -> str:
    """
    Перекласти статус на українську.
    Повертає 'suspicious (підозрілий)' і т.п.
    """
    category = (category or "").lower()
    ua = STATUS_TRANSLATIONS_UA.get(category, "")
    if ua:
        return f"{category} ({ua})"
    return category or "unknown"


def calc_risk(problem_engines: List[Dict[str, Any]]) -> str:
    """
    Обчислити рівень ризику:
    - 0 проблем → green
    - тільки suspicious (1–2) → yellow
    - будь-який phishing/malware/malicious або >=3 проблем → red
    """
    if not problem_engines:
        return "green"

    high_severity = 0
    for e in problem_engines:
        cat = (e.get("category") or "").lower()
        if cat in {"phishing", "malware", "malicious"}:
            high_severity += 1

    total = len(problem_engines)

    if high_severity == 0 and total <= 2:
        return "yellow"

    # будь-який high або багато проблем → червоний
    return "red"


def format_single_domain_result(domain: str, data: Dict[str, Any]) -> Tuple[str, str]:
    """
    Формує текст для одного домена + короткий заголовок для прогресу.
    Повертає (full_text, short_line)
    """
    error = data.get("error")
    if error:
        full = f"❌ *{domain}* — помилка: `{error}`\n"
        short = f"{domain} — ❌ помилка: {error}"
        return full, short

    problem_engines: List[Dict[str, Any]] = data.get("problems", [])
    total_problems = len(problem_engines)

    if total_problems == 0:
        risk = "green"
        full = (
            f"*{domain}* — {RISK_LABELS[risk]}\n"
            f"Статус: *немає проблемних детекторів загроз*.\n"
        )
        short = f"{domain} — {RISK_LABELS[risk]}"
    else:
        risk = calc_risk(problem_engines)
        risk_label = RISK_LABELS[risk]
        det_word = "детекторів" if total_problems != 1 else "детектор"

        full_lines = [
            f"*{domain}* — {risk_label}",
            f"Статус: *{total_problems} проблемн{ 'их' if total_problems != 1 else 'ий' } {det_word} загроз*.",
            "Детектори:",
        ]
        for eng in problem_engines:
            name = eng.get("engine_name", "Unknown")
            cat = eng.get("category") or ""
            full_lines.append(f"- {name} — {translate_status(cat)}")

        vt_link = VT_DOMAIN_GUI.format(domain=domain)
        full_lines.append(
            f"\n🔗 Перевірка у VirusTotal: [{domain}]({vt_link})"
        )

        full = "\n".join(full_lines) + "\n"
        short = f"{domain} — {risk_label}"

    return full, short


def vt_check_domain(domain: str, api_key: str) -> Dict[str, Any]:
    """
    Перевірка домена через API VirusTotal.
    Повертає dict з полями:
    - error: str (якщо помилка)
    - problems: list[{engine_name, category}]
    """
    headers = {"x-apikey": api_key}
    url = VT_DOMAIN_URL.format(domain=domain)

    try:
        resp = requests.get(url, headers=headers, timeout=30)
    except Exception as e:
        logger.exception("HTTP error for domain %s", domain)
        return {"error": f"http_error: {type(e).__name__}"}

    if resp.status_code == 404:
        return {"error": "http_404"}
    if resp.status_code == 401:
        return {"error": "http_401_unauthorized"}
    if resp.status_code == 429:
        return {"error": "http_429_rate_limit"}
    if resp.status_code >= 500:
        return {"error": f"http_{resp.status_code}_server_error"}
    if resp.status_code != 200:
        return {"error": f"http_{resp.status_code}"}

    try:
        data = resp.json()
    except Exception:
        return {"error": "json_parse_error"}

    try:
        attrs = data["data"]["attributes"]
        last_results = attrs.get("last_analysis_results") or {}
    except Exception:
        return {"error": "no_last_analysis_results"}

    problems: List[Dict[str, Any]] = []
    for engine_name, engine_data in last_results.items():
        category = (engine_data.get("category") or "").lower()
        if category in PROBLEM_CATEGORIES:
            problems.append(
                {
                    "engine_name": engine_name,
                    "category": category,
                }
            )

    return {"problems": problems}


def chunk_text(text: str, limit: int = 3800) -> List[str]:
    """
    Ділить великий текст на шматки, які помістяться в одне Telegram-повідомлення.
    """
    if len(text) <= limit:
        return [text]

    parts = []
    while text:
        if len(text) <= limit:
            parts.append(text)
            break
        # намагаємося різати по останньому \n перед лімітом
        cut = text.rfind("\n", 0, limit)
        if cut == -1:
            cut = limit
        parts.append(text[:cut])
        text = text[cut:].lstrip("\n")
    return parts


# ==========================
# КЛАВІАТУРИ
# ==========================

def main_menu_kb() -> InlineKeyboardMarkup:
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(
        InlineKeyboardButton("✅ Разова перевірка доменів", callback_data="one_time_check"),
        InlineKeyboardButton(
            "📅 Щоденна перевірка списків (скоро)", callback_data="daily_coming_soon"
        ),
        InlineKeyboardButton("🔐 Мій API-ключ", callback_data="set_api_key"),
        InlineKeyboardButton("ℹ️ Допомога та ліміти", callback_data="help_limits"),
    )
    return kb


# ==========================
# ХЕНДЛЕРИ
# ==========================

@dp.message_handler(commands=["start", "menu"])
async def cmd_start(message: types.Message):
    user_id = message.from_user.id
    api_key = get_user_api_key(user_id)

    text_lines = [
        "ЙОВ! 👋",
        "Це бот для перевірки доменів через VirusTotal.",
        "",
        "1️⃣ Спочатку вкажи свій API-ключ VirusTotal.",
        "🔒 Ключ зберігається лише для тебе і використовується тільки для перевірок доменів.",
    ]
    if api_key:
        text_lines.append("")
        text_lines.append("✅ API-ключ уже збережений. Можеш одразу перевіряти домени.")
    else:
        text_lines.append("")
        text_lines.append("❗ Зараз API-ключ ще *не збережений*.")

    text_lines.append("")
    text_lines.append("Далі обери режим:")
    text_lines.append("✅ Разова перевірка доменів")
    text_lines.append("📅 Щоденна перевірка списків (щодня о 11:00 за Києвом — _скоро_).")

    await message.answer("\n".join(text_lines), reply_markup=main_menu_kb())


@dp.callback_query_handler(lambda c: c.data == "help_limits")
async def on_help_limits(call: types.CallbackQuery):
    text = (
        "ℹ️ *Допомога та ліміти*\n\n"
        "Бот використовує API VirusTotal.\n"
        "Основні моменти:\n"
        "- На безкоштовному тарифі VT є ліміти запитів на хвилину/добу.\n"
        "- Якщо ти відправиш занадто багато доменів, VT може повернути помилку *429 (rate limit)*.\n"
        "- У разі помилки ліміту бот покаже відповідну позначку.\n\n"
        "Статуси детекторів загроз переводяться приблизно так:\n"
        "- *phishing* → фішинговий (крадіжка даних/карток)\n"
        "- *malware / malicious* → шкідливий сайт / код\n"
        "- *suspicious* → підозрілий\n\n"
        "Орієнтовні рівні ризику:\n"
        f"- {RISK_LABELS['green']} — чистий домен, детектів немає\n"
        f"- {RISK_LABELS['yellow']} — кілька легких підозр (suspicious)\n"
        f"- {RISK_LABELS['red']} — фішинг/малваре, багато детектів\n"
    )
    await call.message.edit_text(text, reply_markup=main_menu_kb())
    await call.answer()


@dp.callback_query_handler(lambda c: c.data == "set_api_key")
async def on_set_api_key(call: types.CallbackQuery):
    user_id = call.from_user.id
    WAITING_API_KEY.add(user_id)

    text = (
        "🔐 *Налаштування API-ключа VirusTotal*\n\n"
        "Надішли свій API-ключ *одним повідомленням*.\n"
        "Бот автоматично збереже його для твого акаунта.\n\n"
        "_Приклад_: `495ae894e66dcd4b...`"
    )
    await call.message.edit_text(text, reply_markup=None)
    await call.answer()


@dp.callback_query_handler(lambda c: c.data == "daily_coming_soon")
async def on_daily_coming_soon(call: types.CallbackQuery):
    text = (
        "📅 Щоденна перевірка списків доменів\n\n"
        "Ця функція зараз у розробці.\n"
        "План: зберігати списки доменів, давати їм назви (наприклад, *PL нутра*), "
        "і щодня о 11:00 за Києвом надсилати оновлений звіт по кожному списку.\n\n"
        "Поки що доступна *разова перевірка доменів*."
    )
    await call.message.edit_text(text, reply_markup=main_menu_kb())
    await call.answer()


@dp.callback_query_handler(lambda c: c.data == "one_time_check")
async def on_one_time_check(call: types.CallbackQuery):
    user_id = call.from_user.id
    api_key = get_user_api_key(user_id)

    if not api_key:
        text = (
            "❗ Спочатку потрібно додати свій API-ключ VirusTotal.\n\n"
            "Натисни *«🔐 Мій API-ключ»* у меню нижче або просто надішли свій ключ "
            "одним повідомленням — я його розпізнаю і збережу."
        )
        await call.message.edit_text(text, reply_markup=main_menu_kb())
        await call.answer()
        return

    WAITING_DOMAINS_ONETIME.add(user_id)

    text = (
        "✅ *Разова перевірка доменів*\n\n"
        "Надішли список доменів *одним повідомленням*.\n"
        "Допускається формат:\n"
        "- з `http/https` або без;\n"
        "- з `www` або без;\n"
        "- через пробіл, кому або з нового рядка.\n\n"
        "_Приклад:_\n"
        "`https://news.heart-is-here.org`\n"
        "`fitnesalasinia.com`\n"
        "`www.healthblog.life`"
    )
    await call.message.edit_text(text)
    await call.answer()


@dp.message_handler(commands=["cancel"])
async def cmd_cancel(message: types.Message):
    user_id = message.from_user.id
    WAITING_API_KEY.discard(user_id)
    WAITING_DOMAINS_ONETIME.discard(user_id)

    await message.answer(
        "✅ Поточну дію скасовано. Повертаюся до головного меню.",
        reply_markup=main_menu_kb(),
    )


@dp.message_handler()
async def on_text_message(message: types.Message):
    """
    Головний текстовий хендлер:
    - якщо користувач очікувано вводить API-ключ → зберігаємо;
    - якщо схоже на API-ключ і ключу ще нема → зберігаємо автоматично;
    - якщо очікуємо список доменів → запускаємо перевірку;
    - інакше показуємо підказку.
    """
    user_id = message.from_user.id
    text = (message.text or "").strip()

    # 1) Якщо користувач у режимі введення API-ключа
    if user_id in WAITING_API_KEY or (
        not get_user_api_key(user_id) and is_probable_vt_api_key(text)
    ):
        if not is_probable_vt_api_key(text):
            await message.answer(
                "Схоже, це не дуже схоже на API-ключ VirusTotal 😅\n"
                "Ключ зазвичай виглядає як 64-символьний hex.\n"
                "Спробуй ще раз або натисни /cancel, щоб скасувати."
            )
            return

        set_user_api_key(user_id, text)
        WAITING_API_KEY.discard(user_id)

        await message.answer(
            "🔐 API-ключ *успішно збережено* для твого акаунта.\n\n"
            "Тепер можеш користуватися разовою перевіркою доменів.",
            reply_markup=main_menu_kb(),
        )
        return

    # 2) Якщо користувач у режимі разової перевірки доменів
    if user_id in WAITING_DOMAINS_ONETIME:
        domains = split_domains_from_text(text)
        if not domains:
            await message.answer(
                "Не знайшов жодного домена в повідомленні 🤔\n"
                "Переконайся, що надсилаєш саме домени, а не щось інше."
            )
            return

        WAITING_DOMAINS_ONETIME.discard(user_id)
        api_key = get_user_api_key(user_id)
        if not api_key:
            await message.answer(
                "❗ Сталася дивна помилка: API-ключ не знайдено.\n"
                "Натисни «🔐 Мій API-ключ» і додай його ще раз.",
                reply_markup=main_menu_kb(),
            )
            return

        await run_one_time_check(message, domains, api_key)
        return

    # 3) Інший текст — просто підказуємо про меню
    await message.answer(
        "Не зовсім зрозумів, що ти маєш на увазі 🧐\n"
        "Скористайся кнопками нижче:",
        reply_markup=main_menu_kb(),
    )


# ==========================
# ЛОГІКА РАЗОВОЇ ПЕРЕВІРКИ
# ==========================

async def run_one_time_check(message: types.Message, domains: List[str], api_key: str):
    """
    Запускає перевірку доменів і показує прогрес + фінальний звіт.
    """
    total = len(domains)
    logger.info("User %s: one-time check of %s domains", message.from_user.id, total)

    progress_msg = await message.answer(
        f"🚀 Починаю перевірку {total} доменів через VirusTotal...\n"
        f"Прогрес: 0/{total}"
    )

    results: List[Tuple[str, Dict[str, Any], str]] = []  # (domain, raw_result, short_line)

    for idx, domain in enumerate(domains, start=1):
        data = vt_check_domain(domain, api_key)
        full_text, short_line = format_single_domain_result(domain, data)
        results.append((domain, data, full_text))

        # оновлюємо повідомлення з прогресом
        try:
            await progress_msg.edit_text(
                f"🚀 Перевірка доменів...\n"
                f"Прогрес: *{idx}/{total}*\n\n"
                f"Останній результат:\n{short_line}"
            )
        except MessageNotModified:
            pass
        except Exception as e:
            logger.warning("Failed to edit progress message: %s", e)

    # Сформувати фінальний звіт
    report_lines = []

    ok_count = 0
    warn_count = 0
    bad_count = 0
    error_count = 0

    for domain, data, _full in results:
        if data.get("error"):
            error_count += 1
            continue
        problems = data.get("problems") or []
        if not problems:
            ok_count += 1
        elif len(problems) <= 2:
            warn_count += 1
        else:
            bad_count += 1

    report_lines.append(
        f"*Готово.*\n"
        f"Усього доменів: *{total}*\n"
        f"✅ Без проблем: *{ok_count}*\n"
        f"⚠️ З 1–2 попередженнями: *{warn_count}*\n"
        f"❌ З великою кількістю детектів: *{bad_count}*\n"
        f"🚫 З помилками перевірки: *{error_count}*\n"
    )

    await progress_msg.edit_text("\n".join(report_lines))

    # Тепер шлемо детальний звіт частинами
    detailed_text = []
    for _domain, _data, full_text in results:
        detailed_text.append(full_text)

    big_report = "\n".join(detailed_text).strip()
    if not big_report:
        big_report = "Немає детальних даних по доменах (усі з помилками?)."

    chunks = chunk_text(big_report)
    for chunk in chunks:
        await message.answer(chunk)

    # наприкінці — повернення до меню
    await message.answer("Повертаюся до головного меню 👇", reply_markup=main_menu_kb())


# ==========================
# MAIN
# ==========================

def main():
    init_db()
    logger.info("Starting bot...")
    executor.start_polling(dp, skip_updates=True)


if __name__ == "__main__":
    main()
