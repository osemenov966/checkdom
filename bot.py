import os
import re
import logging
import asyncio
import csv
import io
from datetime import datetime
from typing import Set, Dict, List, Optional
from collections import defaultdict

import requests
from aiogram import Bot, Dispatcher, types
from aiogram.utils import executor
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton, InputFile
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.dispatcher import FSMContext
from aiogram.dispatcher.filters.state import State, StatesGroup
import aiosqlite

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Проверка обязательных переменных окружения
if "BOT_TOKEN" not in os.environ:
    raise RuntimeError("Не задано BOT_TOKEN. Додай змінну оточення BOT_TOKEN на хостингу з токеном свого Telegram-бота.")

BOT_TOKEN = os.environ["BOT_TOKEN"]
ADMIN_ID = os.environ.get("ADMIN_ID")

# Инициализация бота и диспетчера
bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

# In-memory состояния
WAITING_API_KEY: Set[int] = set()
WAITING_DOMAINS_ONETIME: Set[int] = set()

# Константы
PROBLEM_CATEGORIES = {"malicious", "malware", "phishing", "suspicious"}
CATEGORY_TRANSLATIONS = {
    "phishing": "фішинговий (крадіжка даних/логінів/карток)",
    "malware": "шкідливий (malware)", 
    "malicious": "шкідливий",
    "suspicious": "підозрілий"
}

# Инициализация БД
async def init_db():
    async with aiosqlite.connect("vt_domains_bot.db") as db:
        # Таблица пользователей
        await db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                vt_api_key TEXT
            )
        ''')
        
        # Таблицы для ежедневных списков (фаза 2)
        await db.execute('''
            CREATE TABLE IF NOT EXISTS domain_lists (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                name TEXT NOT NULL,
                daily_enabled INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(user_id)
            )
        ''')
        
        await db.execute('''
            CREATE TABLE IF NOT EXISTS domain_list_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                list_id INTEGER NOT NULL,
                domain TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (list_id) REFERENCES domain_lists(id)
            )
        ''')
        
        await db.commit()

# Вспомогательные функции
def is_valid_vt_key(text: str) -> bool:
    """Проверяет, похож ли текст на VT API ключ"""
    return bool(re.match(r'^[0-9a-fA-F]{64}$', text.strip()))

def normalize_domain(domain: str) -> Optional[str]:
    """Нормализует домен, возвращает None если не валидный"""
    domain = domain.strip().lower()
    
    # Удаляем протокол
    if domain.startswith(('http://', 'https://')):
        domain = domain.split('://', 1)[1]
    
    # Удаляем путь и параметры
    domain = domain.split('/')[0]
    
    # Удаляем порт
    domain = domain.split(':')[0]
    
    # Удаляем www
    if domain.startswith('www.'):
        domain = domain[4:]
    
    # Проверяем что это домен (содержит точку и не пустой)
    if '.' not in domain or not domain:
        return None
    
    return domain

def parse_domains(text: str) -> List[str]:
    """Парсит домены из текста"""
    # Разделяем по пробелам, запятым, новым строкам
    parts = re.split(r'[,\s]+', text.strip())
    
    domains = set()
    for part in parts:
        if not part:
            continue
            
        domain = normalize_domain(part)
        if domain:
            domains.add(domain)
    
    return list(domains)

def translate_category(category: str) -> str:
    """Переводит категорию на украинский"""
    return CATEGORY_TRANSLATIONS.get(category, category)

def calculate_risk_level(problems: List[Dict]) -> tuple:
    """Рассчитывает уровень риска и возвращает (уровень, текст)"""
    if not problems:
        return "green", "🟢 Низький ризик"
    
    # Считаем проблемные категории
    problem_cats = [p["category"] for p in problems]
    high_risk_cats = [cat for cat in problem_cats if cat in ["phishing", "malware", "malicious"]]
    
    if not high_risk_cats and problem_cats.count("suspicious") <= 2:
        return "yellow", "🟡 Середній ризик"
    
    if high_risk_cats or len(problems) >= 3:
        return "red", "🔴 Високий ризик"
    
    return "yellow", "🟡 Середній ризик"

def chunk_text(text: str, limit: int = 3800) -> List[str]:
    """Разбивает текст на части по лимиту символов"""
    if len(text) <= limit:
        return [text]
    
    chunks = []
    while text:
        if len(text) <= limit:
            chunks.append(text)
            break
        
        # Ищем последний перенос строки перед лимитом
        split_pos = text.rfind('\n', 0, limit)
        if split_pos == -1:
            split_pos = limit
        
        chunks.append(text[:split_pos])
        text = text[split_pos:].lstrip()
    
    return chunks

# VirusTotal API
async def check_domain_vt(domain: str, api_key: str) -> Dict:
    """Проверяет домен через VirusTotal API"""
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 404:
            return {"error": "http_404"}
        elif response.status_code == 401:
            return {"error": "http_401_unauthorized"}
        elif response.status_code == 429:
            return {"error": "http_429_rate_limit"}
        elif response.status_code >= 500:
            return {"error": f"http_{response.status_code}_server_error"}
        elif response.status_code != 200:
            return {"error": f"http_{response.status_code}"}
        
        response.raise_for_status()
        
        data = response.json()
        
        # Извлекаем результаты анализа
        last_analysis = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        
        problems = []
        for engine_name, engine_data in last_analysis.items():
            category = engine_data.get("category")
            if category in PROBLEM_CATEGORIES:
                problems.append({
                    "engine_name": engine_name,
                    "category": category
                })
        
        return {"problems": problems}
        
    except requests.exceptions.RequestException as e:
        logger.error(f"HTTP error for domain {domain}: {e}")
        return {"error": f"http_error: {type(e).__name__}"}
    except ValueError as e:
        logger.error(f"JSON parse error for domain {domain}: {e}")
        return {"error": "json_parse_error"}
    except Exception as e:
        logger.error(f"Unexpected error for domain {domain}: {e}")
        return {"error": f"unexpected: {type(e).__name__}"}

# Клавиатуры
def get_main_keyboard() -> InlineKeyboardMarkup:
    """Возвращает главное меню"""
    keyboard = InlineKeyboardMarkup(row_width=1)
    keyboard.add(
        InlineKeyboardButton("✅ Разова перевірка доменів", callback_data="one_time_check"),
        InlineKeyboardButton("📅 Щоденна перевірка списків (скоро)", callback_data="daily_coming_soon"),
        InlineKeyboardButton("🔐 Мій API-ключ", callback_data="set_api_key"),
        InlineKeyboardButton("ℹ️ Допомога та ліміти", callback_data="help_limits")
    )
    return keyboard

def get_back_to_menu_keyboard() -> InlineKeyboardMarkup:
    """Клавиатура с кнопкой назад в меню"""
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("🔙 Назад до меню", callback_data="back_to_menu"))
    return keyboard

def get_report_keyboard() -> InlineKeyboardMarkup:
    """Клавиатура для экспорта отчета"""
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("📎 Отримати звіт файлом", callback_data="export_report"))
    keyboard.add(InlineKeyboardButton("🔙 Назад до меню", callback_data="back_to_menu"))
    return keyboard

# Обработчики команд
@dp.message_handler(commands=['start', 'menu'])
async def cmd_start(message: types.Message):
    """Обработчик команд /start и /menu"""
    user_id = message.from_user.id
    
    # Проверяем есть ли API ключ пользователя
    async with aiosqlite.connect("vt_domains_bot.db") as db:
        cursor = await db.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
        user_data = await cursor.fetchone()
    
    has_api_key = user_data and user_data[0]
    
    welcome_text = """ЙОВ! 👋

Це бот для перевірки доменів через VirusTotal.

1️⃣ Спочатку вкажи свій API-ключ VirusTotal.
🔒 Ключ зберігається лише для тебе і використовується тільки для перевірок доменів.

"""
    
    if has_api_key:
        welcome_text += "✅ API-ключ уже збережений. Можеш одразу перевіряти домени.\n\n"
    else:
        welcome_text += "❗ Зараз API-ключ ще *не збережений*.\n\n"
    
    welcome_text += """Далі обери режим:
✅ Разова перевірка доменів
📅 Щоденна перевірка списків (щодня о 11:00 за Києвом).
"""
    
    await message.answer(welcome_text, reply_markup=get_main_keyboard(), parse_mode="Markdown")

@dp.message_handler(commands=['cancel'])
async def cmd_cancel(message: types.Message):
    """Обработчик команды /cancel"""
    # Сбрасываем состояния
    user_id = message.from_user.id
    WAITING_API_KEY.discard(user_id)
    WAITING_DOMAINS_ONETIME.discard(user_id)
    
    await message.answer("✅ Поточну дію скасовано. Повертаюся до головного меню.", 
                        reply_markup=get_main_keyboard())

# Обработчики callback-ов
@dp.callback_query_handler(text="back_to_menu")
async def callback_back_to_menu(callback_query: types.CallbackQuery):
    """Возврат в главное меню"""
    user_id = callback_query.from_user.id
    WAITING_API_KEY.discard(user_id)
    WAITING_DOMAINS_ONETIME.discard(user_id)
    
    # Проверяем есть ли API ключ пользователя
    async with aiosqlite.connect("vt_domains_bot.db") as db:
        cursor = await db.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
        user_data = await cursor.fetchone()
    
    has_api_key = user_data and user_data[0]
    
    welcome_text = """Повертаюся до головного меню:

"""
    
    if has_api_key:
        welcome_text += "✅ API-ключ уже збережений. Можеш одразу перевіряти домени.\n\n"
    else:
        welcome_text += "❗ Зараз API-ключ ще *не збережений*.\n\n"
    
    welcome_text += "Обери режим роботи:"
    
    await callback_query.message.edit_text(welcome_text, reply_markup=get_main_keyboard(), parse_mode="Markdown")
    await callback_query.answer()

@dp.callback_query_handler(text="set_api_key")
async def callback_set_api_key(callback_query: types.CallbackQuery):
    """Настройка API ключа"""
    user_id = callback_query.from_user.id
    WAITING_API_KEY.add(user_id)
    
    text = """🔐 *Налаштування API-ключа VirusTotal*

Надішли свій API-ключ *одним повідомленням*.
Бот автоматично збереже його для твого акаунта.

_Приклад_: `495ae894e66dcd4b...`"""
    
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=get_back_to_menu_keyboard())
    await callback_query.answer()

@dp.callback_query_handler(text="one_time_check")
async def callback_one_time_check(callback_query: types.CallbackQuery):
    """Разовая проверка доменов"""
    user_id = callback_query.from_user.id
    
    # Проверяем есть ли API ключ
    async with aiosqlite.connect("vt_domains_bot.db") as db:
        cursor = await db.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
        user_data = await cursor.fetchone()
    
    if not user_data or not user_data[0]:
        text = """❗ Спочатку потрібно додати свій API-ключ VirusTotal.

Натисни *«🔐 Мій API-ключ»* у меню нижче або просто надішли свій ключ
одним повідомленням — я його розпізнаю і збережу."""
        await callback_query.message.edit_text(text, reply_markup=get_main_keyboard(), parse_mode="Markdown")
        return
    
    WAITING_DOMAINS_ONETIME.add(user_id)
    
    text = """✅ *Разова перевірка доменів*

Надішли список доменів *одним повідомленням*.
Допускається формат:
- з `http/https` або без;
- з `www` або без;  
- через пробіл, кому або з нового рядка.

_Приклад:_
`https://news.heart-is-here.org`
`fitnesalasinia.com`
`www.healthblog.life`"""
    
    await callback_query.message.edit_text(text, parse_mode="Markdown", reply_markup=get_back_to_menu_keyboard())
    await callback_query.answer()

@dp.callback_query_handler(text="daily_coming_soon")
async def callback_daily_coming_soon(callback_query: types.CallbackQuery):
    """Заглушка для ежедневных проверок"""
    await callback_query.answer("📅 Функція щоденної перевірки списків буде доступна найближчим часом!", show_alert=True)

@dp.callback_query_handler(text="help_limits")
async def callback_help_limits(callback_query: types.CallbackQuery):
    """Помощь и лимиты"""
    text = """ℹ️ *Допомога та ліміти*

Бот використовує API VirusTotal.
Основні моменти:
- На безкоштовному тарифі VT є ліміти запитів на хвилину/добу.
- Якщо ти відправиш занадто багато доменів, VT може повернути помилку *429 (rate limit)*.
- У разі помилки ліміту бот покаже відповідну позначку.

Статуси детекторів загроз переводяться приблизно так:
- *phishing* → фішинговий (крадіжка даних/логінів/карток)
- *malware / malicious* → шкідливий сайт / код  
- *suspicious* → підозрілий

Орієнтовні рівні ризику:
- 🟢 Низький ризик — детектів немає
- 🟡 Середній ризик — кілька легких підозр (suspicious)
- 🔴 Високий ризик — фішинг/малваре, багато детектів"""
    
    await callback_query.message.edit_text(text, reply_markup=get_back_to_menu_keyboard(), parse_mode="Markdown")
    await callback_query.answer()

@dp.callback_query_handler(text="export_report")
async def callback_export_report(callback_query: types.CallbackQuery):
    """Экспорт отчета в файл"""
    await callback_query.answer("Функція експорту буде реалізована в наступній версії!", show_alert=True)

# Обработчики сообщений
@dp.message_handler(content_types=types.ContentType.TEXT)
async def handle_text_message(message: types.Message):
    """Обработка текстовых сообщений"""
    user_id = message.from_user.id
    text = message.text.strip()
    
    # Если пользователь в состоянии ожидания API ключа
    if user_id in WAITING_API_KEY:
        WAITING_API_KEY.discard(user_id)
        
        if is_valid_vt_key(text):
            # Сохраняем ключ в БД
            async with aiosqlite.connect("vt_domains_bot.db") as db:
                await db.execute(
                    "INSERT OR REPLACE INTO users (user_id, vt_api_key) VALUES (?, ?)",
                    (user_id, text)
                )
                await db.commit()
            
            await message.answer(
                "🔐 API-ключ *успішно збережено* для твого акаунта.\n\n"
                "Тепер можеш користуватися разовою перевіркою доменів.",
                reply_markup=get_main_keyboard(),
                parse_mode="Markdown"
            )
        else:
            await message.answer(
                "Схоже, це не дуже схоже на API-ключ VirusTotal 😅\n"
                "Ключ зазвичай виглядає як 64-символьний hex.\n"
                "Спробуй ще раз або натисни /cancel, щоб скасувати.",
                reply_markup=get_back_to_menu_keyboard()
            )
        return
    
    # Если пользователь в состоянии ожидания доменов для разовой проверки
    if user_id in WAITING_DOMAINS_ONETIME:
        domains = parse_domains(text)
        
        if not domains:
            await message.answer(
                "Не знайшов жодного домена в повідомленні 🤔\n"
                "Переконайся, що надсилаєш саме домени, а не щось інше.",
                reply_markup=get_back_to_menu_keyboard()
            )
            return
        
        WAITING_DOMAINS_ONETIME.discard(user_id)
        
        # Получаем API ключ пользователя
        async with aiosqlite.connect("vt_domains_bot.db") as db:
            cursor = await db.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
            user_data = await cursor.fetchone()
        
        if not user_data or not user_data[0]:
            await message.answer(
                "❌ Не знайдено API-ключ. Будь ласка, спочатку встанови ключ.",
                reply_markup=get_main_keyboard()
            )
            return
        
        api_key = user_data[0]
        
        # Запускаем проверку
        await run_one_time_check(message, domains, api_key)
        return
    
    # Автоматическое распознавание API ключа
    if is_valid_vt_key(text):
        # Проверяем нет ли уже ключа у пользователя
        async with aiosqlite.connect("vt_domains_bot.db") as db:
            cursor = await db.execute("SELECT vt_api_key FROM users WHERE user_id = ?", (user_id,))
            user_data = await cursor.fetchone()
        
        if not user_data or not user_data[0]:
            # Сохраняем ключ
            async with aiosqlite.connect("vt_domains_bot.db") as db:
                await db.execute(
                    "INSERT OR REPLACE INTO users (user_id, vt_api_key) VALUES (?, ?)",
                    (user_id, text)
                )
                await db.commit()
            
            await message.answer(
                "🔐 API-ключ *успішно збережено* для твого акаунта.\n\n"
                "Тепер можеш користуватися разовою перевіркою доменів.",
                reply_markup=get_main_keyboard(),
                parse_mode="Markdown"
            )
        else:
            await message.answer(
                "✅ API-ключ вже збережений. Можеш перевіряти домени.",
                reply_markup=get_main_keyboard()
            )
        return
    
    # Непонятный текст
    await message.answer(
        "Не зовсім зрозумів, що ти маєш на увазі 🧐\n"
        "Скористайся кнопками нижче:",
        reply_markup=get_main_keyboard()
    )

# Основная логика проверки доменов
async def run_one_time_check(message: types.Message, domains: List[str], api_key: str):
    """Запускает разовую проверку доменов"""
    total = len(domains)
    progress_msg = await message.answer(f"🚀 Починаю перевірку {total} доменів через VirusTotal...\nПрогрес: 0/{total}")
    
    results = []
    
    for i, domain in enumerate(domains, 1):
        # Проверяем домен
        result = await check_domain_vt(domain, api_key)
        result["domain"] = domain
        results.append(result)
        
        # Обновляем прогресс
        short_line = build_short_line(result)
        try:
            await progress_msg.edit_text(
                f"🚀 Перевірка доменів...\nПрогрес: *{i}/{total}*\n\nОстанній результат:\n{short_line}",
                parse_mode="Markdown"
            )
        except Exception as e:
            logger.warning(f"Could not update progress message: {e}")
        
        # Небольшая задержка чтобы не превысить лимиты VT
        await asyncio.sleep(1)
    
    # Финальный summary
    stats = calculate_stats(results)
    summary_text = build_summary_text(stats, total)
    
    await progress_msg.edit_text(summary_text, reply_markup=get_report_keyboard(), parse_mode="Markdown")
    
    # Детальный отчет
    detailed_report = build_detailed_report(results)
    report_chunks = chunk_text(detailed_report)
    
    for chunk in report_chunks:
        await message.answer(chunk, parse_mode="Markdown")

def build_short_line(result: Dict) -> str:
    """Строит короткую строку результата для прогресса"""
    domain = result["domain"]
    
    if "error" in result:
        return f"{domain} — ❌ помилка: {result['error']}"
    
    problems = result.get("problems", [])
    risk_level, risk_text = calculate_risk_level(problems)
    
    return f"{domain} — {risk_text}"

def calculate_stats(results: List[Dict]) -> Dict:
    """Считает статистику по результатам"""
    stats = {
        "ok_count": 0,
        "warn_count": 0, 
        "bad_count": 0,
        "error_count": 0
    }
    
    for result in results:
        if "error" in result:
            stats["error_count"] += 1
            continue
        
        problems = result.get("problems", [])
        risk_level, _ = calculate_risk_level(problems)
        
        if risk_level == "green":
            stats["ok_count"] += 1
        elif risk_level == "yellow":
            stats["warn_count"] += 1
        elif risk_level == "red":
            stats["bad_count"] += 1
    
    return stats

def build_summary_text(stats: Dict, total: int) -> str:
    """Строит текст сводки"""
    return f"""*Готово.*
Усього доменів: *{total}*
✅ Без проблем: *{stats['ok_count']}*
⚠️ З 1–2 попередженнями: *{stats['warn_count']}*  
❌ З великою кількістю детектів: *{stats['bad_count']}*
🚫 З помилками перевірки: *{stats['error_count']}*"""

def build_detailed_report(results: List[Dict]) -> str:
    """Строит детальный отчет"""
    report_lines = ["*ДЕТАЛЬНИЙ ЗВІТ*\n"]
    
    for result in results:
        domain = result["domain"]
        
        if "error" in result:
            report_lines.append(f"❌ *{domain}* — помилка: `{result['error']}`\n")
            continue
        
        problems = result.get("problems", [])
        risk_level, risk_text = calculate_risk_level(problems)
        
        report_lines.append(f"*{domain}* — {risk_text}")
        
        if not problems:
            report_lines.append("Статус: *немає проблемних детекторів загроз*.")
        else:
            problem_count = len(problems)
            if problem_count == 1:
                status_text = "1 проблемний детектор загроз"
            elif problem_count <= 4:
                status_text = f"{problem_count} проблемні детектори загроз"
            else:
                status_text = f"{problem_count} проблемних детекторів загроз"
            
            report_lines.append(f"Статус: *{status_text}*.")
            
            if problems:
                report_lines.append("Детектори:")
                for problem in problems[:10]:  # Ограничиваем количество для читаемости
                    ukr_category = translate_category(problem["category"])
                    report_lines.append(f"- {problem['engine_name']} — {problem['category']} ({ukr_category})")
                
                if len(problems) > 10:
                    report_lines.append(f"- ... та ще {len(problems) - 10} детекторів")
        
        # Рекомендация
        if risk_level == "green":
            recommendation = "Рекомендація: ризик мінімальний, домен виглядає чистим."
        elif risk_level == "yellow":
            recommendation = "Рекомендація: можна тестувати, але обережно. Не лий великий обсяг трафіку та стеж за детектами."
        else:  # red
            recommendation = "Рекомендація: не рекомендується лити трафік на цей домен. Краще змінити лендинг або домен. Високий ризик блокувань і скарг."
        
        report_lines.append(recommendation)
        
        # Ссылка на VT
        vt_url = f"https://www.virustotal.com/gui/domain/{domain}"
        report_lines.append(f"🔗 [Перевірка у VirusTotal]({vt_url})\n")
    
    return "\n".join(report_lines)

# Запуск бота
async def on_startup(dp):
    """Действия при запуске бота"""
    await init_db()
    logger.info("Бот запущен и готов к работе!")

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)
