import os
import logging
import sqlite3
import re
from datetime import datetime
from zoneinfo import ZoneInfo
import asyncio

from aiogram import Bot, Dispatcher, executor, types
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from aiogram.utils.exceptions import MessageNotModified
import requests
from apscheduler.schedulers.asyncio import AsyncIOScheduler

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Config
try:
    BOT_TOKEN = os.environ["BOT_TOKEN"]
except KeyError:
    raise RuntimeError("Не задано BOT_TOKEN. Додай змінну оточення BOT_TOKEN на хостингу з токеном свого Telegram-бота.")

ADMIN_ID = os.environ.get("ADMIN_ID")  # Optional

# DB setup
DB_FILE = 'vt_domains_bot.db'
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

# Create tables
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY,
    vt_api_key TEXT
)
""")

# For phase 2
cursor.execute("""
CREATE TABLE IF NOT EXISTS domain_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    daily_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
)
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS domain_list_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    list_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (list_id) REFERENCES domain_lists(id)
)
""")

conn.commit()

# States
waiting_api_key = set()
waiting_domains_onetime = set()

# Constants
PROBLEM_CATEGORIES = {"malicious", "malware", "phishing", "suspicious"}
VT_BASE_URL = "https://www.virustotal.com/api/v3/domains/"
VT_GUI_URL = "https://www.virustotal.com/gui/domain/"
KYIV_TZ = ZoneInfo("Europe/Kyiv")

# Translations
CATEGORY_TRANSLATIONS = {
    "phishing": "фішинговий (крадіжка даних/логінів/карток)",
    "malware": "шкідливий (malware)",
    "malicious": "шкідливий",
    "suspicious": "підозрілий",
}

RISK_LEVELS = {
    "green": "🟢 Низький ризик",
    "yellow": "🟡 Середній ризик",
    "red": "🔴 Високий ризик",
}

RECOMMENDATIONS = {
    "red": "Рекомендація: не рекомендується лити трафік на цей домен. Краще змінити лендинг або домен. Високий ризик блокувань і скарг.",
    "yellow": "Рекомендація: можна тестувати, але обережно. Не лий великий обсяг трафіку та стеж за детектами.",
    "green": "Рекомендація: ризик мінімальний, домен виглядає чистим.",
}

# Functions
def is_valid_vt_key(key: str) -> bool:
    return bool(re.match(r'^[0-9a-fA-F]{64}$', key))

def normalize_domain(raw: str) -> str:
    raw = raw.lower().strip()
    raw = re.sub(r'^https?://', '', raw)
    raw = re.sub(r'^www\.', '', raw)
    raw = re.sub(r':\d+', '', raw)
    raw = raw.split('/')[0]
    if '.' not in raw:
        return ''
    return raw

def parse_domains(text: str) -> list:
    fragments = re.split(r'[,\s\n]+', text)
    domains = set()
    for frag in fragments:
        norm = normalize_domain(frag)
        if norm:
            domains.add(norm)
    return list(domains)

def check_domain_vt(domain: str, api_key: str) -> dict:
    url = f"{VT_BASE_URL}{domain}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers, timeout=30)
        if response.status_code == 200:
            data = response.json()
            analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
            if not analysis:
                return {"error": "no_last_analysis_results"}
            problems = []
            for engine, info in analysis.items():
                category = info.get("category")
                if category in PROBLEM_CATEGORIES:
                    problems.append({"engine_name": engine, "category": category})
            return {"problems": problems}
        elif response.status_code == 404:
            return {"error": "http_404"}
        elif response.status_code == 401:
            return {"error": "http_401_unauthorized"}
        elif response.status_code == 429:
            return {"error": "http_429_rate_limit"}
        elif response.status_code >= 500:
            return {"error": f"http_{response.status_code}_server_error"}
        else:
            return {"error": f"http_{response.status_code}"}
    except requests.RequestException as e:
        return {"error": f"http_error: {type(e).__name__}"}
    except ValueError:
        return {"error": "json_parse_error"}

def translate_category(category: str) -> str:
    trans = CATEGORY_TRANSLATIONS.get(category, category)
    return f"{category} ({trans})"

def calculate_risk(problems: list) -> str:
    if not problems:
        return "green"
    severe_count = sum(1 for p in problems if p["category"] in {"phishing", "malware", "malicious"})
    if severe_count > 0 or len(problems) >= 3:
        return "red"
    return "yellow"

def build_short_line(domain: str, result: dict) -> str:
    if "error" in result:
        return f"{domain} — ❌ помилка: {result['error']}"
    risk = calculate_risk(result["problems"])
    return f"{domain} — {RISK_LEVELS[risk]}"

def build_detail_block(domain: str, result: dict) -> str:
    if "error" in result:
        return f"❌ *{domain}* — помилка: `{result['error']}`\n"
    problems = result["problems"]
    risk = calculate_risk(problems)
    block = f"*{domain}* — {RISK_LEVELS[risk]}\n"
    if not problems:
        block += "Статус: *немає проблемних детекторів загроз*.\n"
    else:
        count = len(problems)
        block += f"Статус: *{count} проблемний детектор загроз*.\n" if count == 1 else f"Статус: *{count} проблемних детекторів загроз*.\n"
        block += "Детектори:\n"
        for p in problems:
            block += f"- {p['engine_name']} — {translate_category(p['category'])}\n"
    block += f"🔗 [Перевірка у VirusTotal]({VT_GUI_URL}{domain})\n"
    block += f"{RECOMMENDATIONS[risk]}\n\n"
    return block

def chunk_text(text: str, limit=3800) -> list:
    if len(text) <= limit:
        return [text]
    chunks = []
    current = ""
    for line in text.split("\n"):
        if len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = line + "\n"
        else:
            current += line + "\n"
    if current:
        chunks.append(current)
    return chunks

async def run_one_time_check(message: types.Message, domains: list, api_key: str):
    user_id = message.from_user.id
    total = len(domains)
    logger.info(f"User {user_id} starting one-time check for {total} domains")
    progress_msg = await message.reply(f"🚀 Починаю перевірку {total} доменів через VirusTotal...\nПрогрес: 0/{total}")
    results = []
    ok_count = warn_count = bad_count = error_count = 0
    for i, domain in enumerate(domains, 1):
        result = check_domain_vt(domain, api_key)
        results.append((domain, result))
        short_line = build_short_line(domain, result)
        new_text = f"🚀 Перевірка доменів...\nПрогрес: *{i}/{total}*\nОстанній результат:\n{short_line}"
        try:
            await bot.edit_message_text(new_text, message.chat.id, progress_msg.message_id, parse_mode="Markdown")
        except MessageNotModified:
            pass
        await asyncio.sleep(1)  # To avoid rate limits
        if "error" in result:
            error_count += 1
        else:
            risk = calculate_risk(result["problems"])
            if risk == "green":
                ok_count += 1
            elif risk == "yellow":
                warn_count += 1
            else:
                bad_count += 1

    # Final progress edit
    summary = f"*Готово.*\nУсього доменів: *{total}*\n✅ Без проблем: *{ok_count}*\n⚠️ З 1–2 попередженнями: *{warn_count}*\n❌ З великою кількістю детектів: *{bad_count}*\n🚫 З помилками перевірки: *{error_count}*"
    await bot.edit_message_text(summary, message.chat.id, progress_msg.message_id, parse_mode="Markdown")

    # Detailed report
    big_report = ""
    for domain, result in results:
        big_report += build_detail_block(domain, result)
    chunks = chunk_text(big_report)
    for chunk in chunks:
        await message.reply(chunk, parse_mode="Markdown", disable_web_page_preview=True)

    # Export button
    export_kb = InlineKeyboardMarkup()
    export_kb.add(InlineKeyboardButton("📎 Отримати звіт файлом", callback_data=f"export_onetime_{user_id}"))
    await message.reply("Звіт готовий. Бажаєш завантажити файл?", reply_markup=export_kb)

async def generate_csv(results: list, user_id: int) -> str:
    import io
    import csv
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["domain", "risk_level", "risk_label_ua", "status_summary_ua", "detectors", "error"])
    for domain, result in results:
        if "error" in result:
            writer.writerow([domain, "", "", "", "", result["error"]])
            continue
        problems = result["problems"]
        risk = calculate_risk(problems)
        risk_label = RISK_LEVELS[risk]
        if not problems:
            status_summary = "немає проблемних детекторів"
        else:
            status_summary = f"{len(problems)} проблемних детекторів"
        detectors = "; ".join(f"{p['engine_name']}: {translate_category(p['category'])}" for p in problems)
        writer.writerow([domain, risk, risk_label, status_summary, detectors, ""])
    filename = f"domains_report_{datetime.now().strftime('%Y-%m-%d_%H%M')}_user_{user_id}.csv"
    return filename, output.getvalue()

def get_user_api_key(user_id: int) -> str:
    cursor.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
    row = cursor.fetchone()
    return row[0] if row else None

def save_user_api_key(user_id: int, api_key: str):
    cursor.execute("INSERT OR REPLACE INTO users (user_id, vt_api_key) VALUES (?, ?)", (user_id, api_key))
    conn.commit()

async def show_main_menu(message: types.Message, edit=False):
    user_id = message.from_user.id
    api_key = get_user_api_key(user_id)
    text = "ЙОВ! 👋\nЦе бот для перевірки доменів через VirusTotal.\n\n1️⃣ Спочатку вкажи свій API-ключ VirusTotal.\n🔒 Ключ зберігається лише для тебе і використовується тільки для перевірок доменів.\n"
    if api_key:
        text += "\n✅ API-ключ уже збережений. Можеш одразу перевіряти домени.\n"
    else:
        text += "\n❗ Зараз API-ключ ще *не збережений*.\n"
    text += "\nДалі обери режим:\n✅ Разова перевірка доменів\n📅 Щоденна перевірка списків (щодня о 11:00 за Києвом)."
    kb = InlineKeyboardMarkup(row_width=1)
    kb.add(InlineKeyboardButton("✅ Разова перевірка доменів", callback_data="one_time_check"))
    kb.add(InlineKeyboardButton("📅 Щоденна перевірка списків (скоро)", callback_data="daily_coming_soon"))
    kb.add(InlineKeyboardButton("🔐 Мій API-ключ", callback_data="set_api_key"))
    kb.add(InlineKeyboardButton("ℹ️ Допомога та ліміти", callback_data="help_limits"))
    if edit:
        await bot.edit_message_text(text, message.chat.id, message.message_id, parse_mode="Markdown", reply_markup=kb)
    else:
        await message.reply(text, parse_mode="Markdown", reply_markup=kb)

# Handlers
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

@dp.message_handler(commands=['start', 'menu'])
async def start_handler(message: types.Message):
    await show_main_menu(message)

@dp.message_handler(commands=['cancel'])
async def cancel_handler(message: types.Message):
    user_id = message.from_user.id
    waiting_api_key.discard(user_id)
    waiting_domains_onetime.discard(user_id)
    await message.reply("✅ Поточну дію скасовано. Повертаюся до головного меню.")
    await show_main_menu(message)

@dp.callback_query_handler(lambda c: c.data == "set_api_key")
async def set_api_key_handler(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    waiting_api_key.add(user_id)
    text = "🔐 *Налаштування API-ключа VirusTotal*\n\nНадішли свій API-ключ *одним повідомленням*.\nБот автоматично збереже його для твого акаунта.\n\n_Приклад_: `495ae894e66dcd4b...`"
    await callback.message.reply(text, parse_mode="Markdown")
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "one_time_check")
async def one_time_check_handler(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    api_key = get_user_api_key(user_id)
    if not api_key:
        text = "❗ Спочатку потрібно додати свій API-ключ VirusTotal.\n\nНатисни *«🔐 Мій API-ключ»* у меню нижче або просто надішли свій ключ\nодним повідомленням — я його розпізнаю і збережу."
        await callback.message.reply(text, parse_mode="Markdown")
        await show_main_menu(callback.message, edit=False)
    else:
        waiting_domains_onetime.add(user_id)
        text = "✅ *Разова перевірка доменів*\n\nНадішли список доменів *одним повідомленням*.\nДопускається формат:\n- з `http/https` або без;\n- з `www` або без;\n- через пробіл, кому або з нового рядка.\n\n_Приклад:_\n`https://news.heart-is-here.org`\n`fitnesalasinia.com`\n`www.healthblog.life`"
        await callback.message.reply(text, parse_mode="Markdown")
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data.startswith("export_onetime_"))
async def export_handler(callback: types.CallbackQuery):
    # Note: For real implementation, store results temporarily in memory or DB. Here, as stub, assume results are available.
    # For simplicity, this is a placeholder since results are not stored.
    await callback.answer("Експорт файлу поки не реалізований у фазі 1.")
    # To implement: use a dict user_results[user_id] = results, set after check, clear after export.

@dp.callback_query_handler(lambda c: c.data == "daily_coming_soon")
async def daily_stub_handler(callback: types.CallbackQuery):
    await callback.answer("Щоденна перевірка списків буде доступна у фазі 2.")
    text = "📅 Щоденна перевірка списків доменів (скоро).\nПоки ця функція в розробці."
    await callback.message.reply(text)

@dp.callback_query_handler(lambda c: c.data == "help_limits")
async def help_limits_handler(callback: types.CallbackQuery):
    text = "ℹ️ *Допомога та ліміти*\n\nБот використовує API VirusTotal.\nОсновні моменти:\n- На безкоштовному тарифі VT є ліміти запитів на хвилину/добу.\n- Якщо ти відправиш занадто багато доменів, VT може повернути помилку *429 (rate limit)*.\n- У разі помилки ліміту бот покаже відповідну позначку.\n\nСтатуси детекторів загроз переводяться приблизно так:\n- *phishing* → фішинговий (крадіжка даних/логінів/карток)\n- *malware / malicious* → шкідливий сайт / код\n- *suspicious* → підозрілий\n\nОрієнтовні рівні ризику:\n- 🟢 Низький ризик — детектів немає\n- 🟡 Середній ризик — кілька легких підозр (suspicious)\n- 🔴 Високий ризик — фішинг/малваре, багато детектів"
    await callback.message.reply(text, parse_mode="Markdown")
    await callback.answer()

@dp.message_handler()
async def message_handler(message: types.Message):
    user_id = message.from_user.id
    text = message.text.strip()
    api_key = get_user_api_key(user_id)
    if user_id in waiting_api_key:
        if not is_valid_vt_key(text):
            await message.reply("Схоже, це не дуже схоже на API-ключ VirusTotal 😅\nКлюч зазвичай виглядає як 64-символьний hex.\nСпробуй ще раз або натисни /cancel, щоб скасувати.")
            return
        save_user_api_key(user_id, text)
        waiting_api_key.discard(user_id)
        await message.reply("🔐 API-ключ *успішно збережено* для твого акаунта.\n\nТепер можеш користуватися разовою перевіркою доменів.", parse_mode="Markdown")
        await show_main_menu(message)
    elif user_id in waiting_domains_onetime:
        domains = parse_domains(text)
        if not domains:
            await message.reply("Не знайшов жодного домена в повідомленні 🤔\nПереконайся, що надсилаєш саме домени, а не щось інше.")
            return
        waiting_domains_onetime.discard(user_id)
        await run_one_time_check(message, domains, api_key)
    elif not api_key and is_valid_vt_key(text):
        save_user_api_key(user_id, text)
        await message.reply("🔐 API-ключ *успішно збережено* для твого акаунта.\n\nТепер можеш користуватися разовою перевіркою доменів.", parse_mode="Markdown")
        await show_main_menu(message)
    else:
        await message.reply("Не зовсім зрозумів, що ти маєш на увазі 🧐\nСкористайся кнопками нижче:")
        await show_main_menu(message)

# Scheduler for phase 2 (stub)
scheduler = AsyncIOScheduler(timezone=KYIV_TZ)

async def daily_check():
    # Stub: Implement in phase 2
    pass

scheduler.add_job(daily_check, 'cron', hour=11, minute=0)

async def on_startup(_):
    scheduler.start()
    logger.info("Bot started")

if __name__ == '__main__':
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)
