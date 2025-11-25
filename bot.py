import os
import re
import logging
import asyncio
import csv
import io
from datetime import datetime
from typing import Dict, List, Optional

import requests
from aiogram import Bot, Dispatcher, types
from aiogram.utils import executor
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton
import aiosqlite

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Проверка токена
if "BOT_TOKEN" not in os.environ:
    raise RuntimeError("Не задано BOT_TOKEN")

BOT_TOKEN = os.environ["BOT_TOKEN"]
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

# Глобальные переменные для состояний
user_states = {}
user_last_report = {}

# Константы
PROBLEM_CATEGORIES = {"malicious", "malware", "phishing", "suspicious"}
CATEGORY_TRANSLATIONS = {
    "phishing": "фішинговий",
    "malware": "шкідливий", 
    "malicious": "шкідливий",
    "suspicious": "підозрілий"
}

# Инициализация БД
async def init_db():
    async with aiosqlite.connect("vt_bot.db") as db:
        await db.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY,
                api_key TEXT
            )
        ''')
        await db.commit()

# Клавиатуры
def main_menu():
    keyboard = InlineKeyboardMarkup()
    keyboard.row(InlineKeyboardButton("✅ Перевірити домени", callback_data="check_domains"))
    keyboard.row(InlineKeyboardButton("🔐 Мій API ключ", callback_data="set_key"))
    keyboard.row(InlineKeyboardButton("ℹ️ Допомога", callback_data="help"))
    return keyboard

def back_button():
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("🔙 Назад", callback_data="main_menu"))
    return keyboard

# Вспомогательные функции
def is_valid_key(text):
    return bool(re.match(r'^[0-9a-fA-F]{64}$', text.strip()))

def parse_domains(text):
    parts = re.split(r'[,\s\n]+', text.strip())
    domains = set()
    for part in parts:
        part = part.strip().lower()
        if not part:
            continue
            
        # Удаляем протокол и путь
        if part.startswith(('http://', 'https://')):
            part = part.split('://', 1)[1]
        part = part.split('/')[0]
        part = part.split(':')[0]
        
        if part.startswith('www.'):
            part = part[4:]
            
        if '.' in part and part:
            domains.add(part)
            
    return list(domains)

def get_risk_level(problems):
    if not problems:
        return "🟢 Низький ризик", "green"
    
    categories = [p["category"] for p in problems]
    high_risk = any(cat in ["phishing", "malware", "malicious"] for cat in categories)
    
    if not high_risk and categories.count("suspicious") <= 2:
        return "🟡 Середній ризик", "yellow"
    
    return "🔴 Високий ризик", "red"

# VirusTotal API
async def check_domain(domain, api_key):
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    
    try:
        response = requests.get(url, headers=headers, timeout=30)
        
        if response.status_code == 401:
            return {"error": "Невірний API ключ"}
        elif response.status_code == 404:
            return {"error": "Домен не знайдено"}
        elif response.status_code == 429:
            return {"error": "Перевищено ліміт запитів"}
        elif response.status_code != 200:
            return {"error": f"Помилка API: {response.status_code}"}
            
        data = response.json()
        results = data.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
        
        problems = []
        for engine, result in results.items():
            category = result.get("category")
            if category in PROBLEM_CATEGORIES:
                problems.append({
                    "engine_name": engine,
                    "category": category
                })
                
        return {"problems": problems}
        
    except Exception as e:
        return {"error": f"Помилка мережі: {str(e)}"}

# Обработчики команд
@dp.message_handler(commands=['start', 'menu'])
async def cmd_start(message: types.Message):
    user_id = message.from_user.id
    
    # Проверяем наличие API ключа
    async with aiosqlite.connect("vt_bot.db") as db:
        cursor = await db.execute("SELECT api_key FROM users WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
    
    has_key = bool(row and row[0])
    
    text = """ЙОВ! 👋

Це бот для перевірки доменів через VirusTotal.

"""
    
    if has_key:
        text += "✅ API ключ збережений\n\n"
    else:
        text += "❌ API ключ не встановлений\n\n"
        
    text += "Оберіть дію:"
    
    await message.answer(text, reply_markup=main_menu())

@dp.message_handler(commands=['cancel'])
async def cmd_cancel(message: types.Message):
    user_id = message.from_user.id
    user_states.pop(user_id, None)
    await message.answer("Дію скасовано", reply_markup=main_menu())

# Обработчики кнопок
@dp.callback_query_handler(lambda c: c.data == "main_menu")
async def main_menu_callback(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    user_states.pop(user_id, None)
    
    async with aiosqlite.connect("vt_bot.db") as db:
        cursor = await db.execute("SELECT api_key FROM users WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
    
    has_key = bool(row and row[0])
    
    text = "Головне меню:\n"
    text += "✅ API ключ збережений\n" if has_key else "❌ API ключ не встановлений\n"
    
    await callback.message.edit_text(text, reply_markup=main_menu())
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "set_key")
async def set_key_callback(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    user_states[user_id] = "waiting_key"
    
    text = """🔐 Надішліть ваш VirusTotal API ключ

Ключ має 64 символи (hex-рядок)
Приклад: 495ae894e66dcd4b..."""
    
    await callback.message.edit_text(text, reply_markup=back_button())
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "check_domains")
async def check_domains_callback(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    
    # Проверяем API ключ
    async with aiosqlite.connect("vt_bot.db") as db:
        cursor = await db.execute("SELECT api_key FROM users WHERE user_id = ?", (user_id,))
        row = await cursor.fetchone()
    
    if not row or not row[0]:
        text = "❌ Спочатку встановіть API ключ"
        await callback.message.edit_text(text, reply_markup=back_button())
        await callback.answer()
        return
    
    user_states[user_id] = "waiting_domains"
    
    text = """✅ Надішліть список доменів

Формат:
- Через пробіл, кому або з нового рядка
- З http/https або без
- З www або без

Приклад:
example.com
https://site.com
www.test.org"""
    
    await callback.message.edit_text(text, reply_markup=back_button())
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "help")
async def help_callback(callback: types.CallbackQuery):
    text = """ℹ️ Допомога

• API ключ отримуйте на virustotal.com
• Безкоштовний тариф має обмеження
• Статуси:
  🟢 Безпечний
  🟡 Підозрілий  
  🔴 Небезпечний
  
• Детектори:
  - phishing - фішинг
  - malware - шкідливе ПЗ
  - malicious - шкідливий
  - suspicious - підозрілий"""
    
    await callback.message.edit_text(text, reply_markup=back_button())
    await callback.answer()

# Обработка сообщений
@dp.message_handler(content_types=types.ContentType.TEXT)
async def handle_message(message: types.Message):
    user_id = message.from_user.id
    text = message.text.strip()
    state = user_states.get(user_id)
    
    # Обработка API ключа
    if state == "waiting_key":
        if is_valid_key(text):
            async with aiosqlite.connect("vt_bot.db") as db:
                await db.execute(
                    "INSERT OR REPLACE INTO users (user_id, api_key) VALUES (?, ?)",
                    (user_id, text)
                )
                await db.commit()
            
            user_states.pop(user_id, None)
            await message.answer("✅ API ключ збережено", reply_markup=main_menu())
        else:
            await message.answer("❌ Невірний формат ключа. Спробуйте ще раз:", reply_markup=back_button())
        return
    
    # Обработка доменов
    elif state == "waiting_domains":
        domains = parse_domains(text)
        if not domains:
            await message.answer("❌ Не знайдено доменів. Спробуйте ще раз:", reply_markup=back_button())
            return
        
        user_states.pop(user_id, None)
        
        # Получаем API ключ
        async with aiosqlite.connect("vt_bot.db") as db:
            cursor = await db.execute("SELECT api_key FROM users WHERE user_id = ?", (user_id,))
            row = await cursor.fetchone()
        
        if not row:
            await message.answer("❌ API ключ не знайдено", reply_markup=main_menu())
            return
        
        api_key = row[0]
        await process_domains_check(message, domains, api_key)
        return
    
    # Авто-определение API ключа
    elif is_valid_key(text):
        async with aiosqlite.connect("vt_bot.db") as db:
            await db.execute(
                "INSERT OR REPLACE INTO users (user_id, api_key) VALUES (?, ?)",
                (user_id, text)
            )
            await db.commit()
        
        await message.answer("✅ API ключ збережено", reply_markup=main_menu())
        return
    
    # Неизвестное сообщение
    await message.answer("Оберіть дію з меню:", reply_markup=main_menu())

# Основная логика проверки
async def process_domains_check(message: types.Message, domains: list, api_key: str):
    total = len(domains)
    progress_msg = await message.answer(f"🔍 Перевіряю {total} доменів...\n0/{total}")
    
    results = []
    
    for i, domain in enumerate(domains, 1):
        result = await check_domain(domain, api_key)
        result["domain"] = domain
        results.append(result)
        
        # Обновляем прогресс
        status = "✅" if "error" not in result and not result.get("problems") else "⚠️" if "error" not in result else "❌"
        try:
            await progress_msg.edit_text(
                f"🔍 Перевіряю {total} доменів...\n{i}/{total}\n\nОстанній: {domain} {status}"
            )
        except:
            pass
        
        await asyncio.sleep(0.5)  # Задержка между запросами
    
    # Сохраняем отчет
    user_last_report[message.from_user.id] = results
    
    # Показываем итоги
    stats = {"ok": 0, "warn": 0, "bad": 0, "error": 0}
    for result in results:
        if "error" in result:
            stats["error"] += 1
        else:
            _, level = get_risk_level(result.get("problems", []))
            if level == "green": stats["ok"] += 1
            elif level == "yellow": stats["warn"] += 1
            else: stats["bad"] += 1
    
    summary = f"""📊 Результати перевірки

• Усього доменів: {total}
• 🟢 Безпечних: {stats['ok']}
• 🟡 Підозрілих: {stats['warn']}  
• 🔴 Небезпечних: {stats['bad']}
• ❌ Помилок: {stats['error']}"""

    keyboard = InlineKeyboardMarkup()
    keyboard.row(InlineKeyboardButton("📋 Детальний звіт", callback_data="detailed_report"))
    keyboard.row(InlineKeyboardButton("📎 Експорт CSV", callback_data="export_csv"))
    keyboard.row(InlineKeyboardButton("🔙 Головне меню", callback_data="main_menu"))
    
    await progress_msg.edit_text(summary, reply_markup=keyboard)
    
    # Отправляем детальный отчет частями
    await send_detailed_report(message, results)

async def send_detailed_report(message: types.Message, results: list):
    report_parts = []
    current_part = "📋 Детальний звіт:\n\n"
    
    for result in results:
        domain = result["domain"]
        
        if "error" in result:
            line = f"❌ {domain}\nПомилка: {result['error']}\n\n"
        else:
            problems = result.get("problems", [])
            risk_text, level = get_risk_level(problems)
            
            line = f"{risk_text} - {domain}\n"
            
            if not problems:
                line += "• Детекторів не знайдено\n"
            else:
                line += f"• Детекторів: {len(problems)}\n"
                for problem in problems[:3]:  # Показываем первые 3 детектора
                    ukr_cat = CATEGORY_TRANSLATIONS.get(problem["category"], problem["category"])
                    line += f"  - {problem['engine_name']}: {ukr_cat}\n"
            
            line += f"• [Перевірити в VT](https://www.virustotal.com/gui/domain/{domain})\n\n"
        
        # Если часть становится слишком большой, отправляем и начинаем новую
        if len(current_part + line) > 4000:
            report_parts.append(current_part)
            current_part = line
        else:
            current_part += line
    
    if current_part:
        report_parts.append(current_part)
    
    # Отправляем части отчета
    for part in report_parts:
        await message.answer(part, parse_mode="Markdown", disable_web_page_preview=True)

# Дополнительные callback-ы
@dp.callback_query_handler(lambda c: c.data == "detailed_report")
async def detailed_report_callback(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    results = user_last_report.get(user_id)
    
    if not results:
        await callback.answer("Звіт не знайдено")
        return
    
    keyboard = InlineKeyboardMarkup()
    keyboard.add(InlineKeyboardButton("🔙 Назад", callback_data="main_menu"))
    
    await callback.message.answer("📋 Завантажую детальний звіт...")
    await send_detailed_report(callback.message, results)
    await callback.answer()

@dp.callback_query_handler(lambda c: c.data == "export_csv")
async def export_csv_callback(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    results = user_last_report.get(user_id)
    
    if not results:
        await callback.answer("Дані для експорту не знайдено")
        return
    
    # Создаем CSV в памяти
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Домен", "Ризик", "Детектори", "Помилка"])
    
    for result in results:
        domain = result["domain"]
        
        if "error" in result:
            writer.writerow([domain, "", "", result["error"]])
        else:
            risk_text, level = get_risk_level(result.get("problems", []))
            detectors = ", ".join([
                f"{p['engine_name']}({p['category']})" 
                for p in result.get("problems", [])
            ])
            writer.writerow([domain, risk_text, detectors, ""])
    
    # Создаем файл
    csv_data = output.getvalue().encode('utf-8')
    file = io.BytesIO(csv_data)
    file.name = f"vt_report_{datetime.now().strftime('%Y%m%d_%H%M')}.csv"
    
    await callback.message.answer_document(file, caption="📎 Експорт у CSV")
    await callback.answer()

# Запуск бота
async def on_startup(_):
    await init_db()
    logger.info("Бот запущений!")

if __name__ == "__main__":
    executor.start_polling(dp, skip_updates=True, on_startup=on_startup)
