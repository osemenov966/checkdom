import os
import logging
from aiogram import Bot, Dispatcher, types
from aiogram.contrib.fsm_storage.memory import MemoryStorage
from aiogram.utils import executor

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Получение токена бота
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("Не задано BOT_TOKEN. Додай змінну оточення BOT_TOKEN на хостингу з токеном свого Telegram-бота.")

# Инициализация бота и диспетчера
bot = Bot(token=BOT_TOKEN)
storage = MemoryStorage()
dp = Dispatcher(bot, storage=storage)

# In-memory состояния (упрощённо)
WAITING_API_KEY = set()
WAITING_DOMAINS_ONETIME = set()

# "База данных" в памяти для теста
user_data = {}

# Клавиатура главного меню
def get_main_menu_keyboard():
    keyboard = types.InlineKeyboardMarkup(row_width=1)
    keyboard.add(
        types.InlineKeyboardButton("✅ Разова перевірка доменів", callback_data="one_time_check"),
        types.InlineKeyboardButton("📅 Щоденна перевірка списків", callback_data="daily_coming_soon"),
        types.InlineKeyboardButton("🔐 Мій API-ключ", callback_data="set_api_key"),
        types.InlineKeyboardButton("ℹ️ Допомога та ліміти", callback_data="help_limits")
    )
    return keyboard

# Команда /start
@dp.message_handler(commands=['start', 'menu'])
async def start_command(message: types.Message):
    user_id = message.from_user.id
    
    welcome_text = (
        "ЙОВ! 👋\n"
        "Це бот для перевірки доменів через VirusTotal.\n\n"
        "1️⃣ Спочатку вкажи свій API-ключ VirusTotal.\n"
        "🔒 Ключ зберігається лише для тебе і використовується тільки для перевірок доменів.\n\n"
    )
    
    if user_id in user_data and user_data[user_id].get('vt_api_key'):
        welcome_text += "✅ API-ключ уже збережений. Можеш одразу перевіряти домени.\n\n"
    else:
        welcome_text += "❗ Зараз API-ключ ще *не збережений*.\n\n"
    
    welcome_text += (
        "Далі обери режим:\n"
        "✅ Разова перевірка доменів\n"
        "📅 Щоденна перевірка списків (щодня о 11:00 за Києвом).\n"
    )
    
    await message.answer(welcome_text, reply_markup=get_main_menu_keyboard())

# Команда /cancel
@dp.message_handler(commands=['cancel'])
async def cancel_command(message: types.Message):
    user_id = message.from_user.id
    WAITING_API_KEY.discard(user_id)
    WAITING_DOMAINS_ONETIME.discard(user_id)
    
    await message.answer("✅ Поточну дію скасовано. Повертаюся до головного меню.", 
                         reply_markup=get_main_menu_keyboard())

# Обработчик кнопки "Разова перевірка"
@dp.callback_query_handler(text="one_time_check")
async def one_time_check_callback(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    
    # Проверяем наличие API ключа
    if user_id not in user_data or not user_data[user_id].get('vt_api_key'):
        await callback.answer("❗ Спочатку налаштуй API-ключ!", show_alert=True)
        
        text = (
            "❗ Спочатку потрібно додати свій API-ключ VirusTotal.\n\n"
            "Натисни *«🔐 Мій API-ключ»* у меню нижче або просто надішли свій ключ "
            "одним повідомленням - я його розпізнаю і збережу."
        )
        await callback.message.answer(text, reply_markup=get_main_menu_keyboard())
        return
    
    await callback.answer()  # Убираем "загрузку"
    
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
    await callback.message.answer(text)

# Обработчик кнопки "Мій API-ключ"
@dp.callback_query_handler(text="set_api_key")
async def set_api_key_callback(callback: types.CallbackQuery):
    await callback.answer()  # Убираем "загрузку"
    
    WAITING_API_KEY.add(callback.from_user.id)
    text = (
        "🔐 *Налаштування API-ключа VirusTotal*\n\n"
        "Надішли свій API-ключ *одним повідомленням*.\n"
        "Бот автоматично збереже його для твого акаунта.\n\n"
        "_Приклад_: `495ae894e66dcd4b...`"
    )
    await callback.message.answer(text)

# Обработчик кнопки "Допомога та ліміти"
@dp.callback_query_handler(text="help_limits")
async def help_limits_callback(callback: types.CallbackQuery):
    await callback.answer()  # Убираем "загрузку"
    
    text = (
        "ℹ️ *Допомога та ліміти*\n\n"
        "Бот використовує API VirusTotal.\n"
        "Основні моменти:\n"
        "- На безкоштовному тарифі VT є ліміти запитів на хвилину/добу.\n"
        "- Якщо ти відправиш занадто багато доменів, VT може повернути помилку *429 (rate limit)*.\n\n"
        "Статуси детекторів загроз:\n"
        "- *phishing* → фішинговий\n"
        "- *malware / malicious* → шкідливий\n"
        "- *suspicious* → підозрілий\n\n"
        "Рівні ризику:\n"
        "🟢 Низький ризик — детектів немає\n"
        "🟡 Середній ризик — кілька підозр\n"
        "🔴 Високий ризик — фішинг/малваре"
    )
    await callback.message.answer(text, reply_markup=get_main_menu_keyboard())

# Обработчик кнопки "Щоденна перевірка" (заглушка)
@dp.callback_query_handler(text="daily_coming_soon")
async def daily_coming_soon_callback(callback: types.CallbackQuery):
    await callback.answer("📅 Ця функція з'явиться в наступних оновленнях!", show_alert=True)

# Обработка API ключа
@dp.message_handler(lambda message: message.from_user.id in WAITING_API_KEY)
async def process_api_key(message: types.Message):
    user_id = message.from_user.id
    api_key = message.text.strip()
    
    # Простая проверка формата ключа (64 hex символа)
    if len(api_key) == 64 and all(c in '0123456789abcdefABCDEF' for c in api_key):
        # Сохраняем ключ
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['vt_api_key'] = api_key
        
        WAITING_API_KEY.discard(user_id)
        await message.answer(
            "🔐 API-ключ *успішно збережено* для твого акаунта.\n\n"
            "Тепер можеш користуватися разовою перевіркою доменів.",
            reply_markup=get_main_menu_keyboard()
        )
    else:
        await message.answer(
            "Схоже, це не дуже схоже на API-ключ VirusTotal 😅\n"
            "Ключ зазвичай виглядає як 64-символьний hex.\n"
            "Спробуй ще раз або натисни /cancel, щоб скасувати."
        )

# Обработка доменов для проверки
@dp.message_handler(lambda message: message.from_user.id in WAITING_DOMAINS_ONETIME)
async def process_domains(message: types.Message):
    user_id = message.from_user.id
    domains_text = message.text
    
    # Простая имитация парсинга доменов
    domains = []
    for line in domains_text.split('\n'):
        for part in line.split(','):
            for domain in part.split():
                domain = domain.strip()
                if '.' in domain and ' ' not in domain:
                    # Простая нормализация
                    domain = domain.lower().replace('http://', '').replace('https://', '').replace('www.', '')
                    if '/' in domain:
                        domain = domain.split('/')[0]
                    domains.append(domain)
    
    domains = list(set(domains))  # Убираем дубли
    
    if not domains:
        await message.answer(
            "Не знайшов жодного домена в повідомленні 🤔\n"
            "Переконайся, що надсилаєш саме домени, а не щось інше."
        )
        return
    
    WAITING_DOMAINS_ONETIME.discard(user_id)
    
    # Имитация проверки доменов
    progress_msg = await message.answer(f"🚀 Починаю перевірку {len(domains)} доменів...\nПрогрес: 0/{len(domains)}")
    
    results = []
    for i, domain in enumerate(domains, 1):
        # Имитация задержки проверки
        import asyncio
        await asyncio.sleep(1)
        
        # Случайный результат для демонстрации
        import random
        risk_level = random.choice(['🟢 Низький ризик', '🟡 Середній ризик', '🔴 Високий ризик'])
        
        short_line = f"{domain} — {risk_level}"
        results.append(short_line)
        
        # Обновляем прогресс
        progress_text = f"🚀 Перевірка доменів...\nПрогрес: {i}/{len(domains)}\n\nОстанній результат:\n{short_line}"
        await progress_msg.edit_text(progress_text)
    
    # Финальный результат
    summary = (
        f"*Готово.*\n"
        f"Усього доменів: *{len(domains)}*\n"
        f"✅ Без проблем: *{len([r for r in results if '🟢' in r])}*\n"
        f"🟡 З попередженнями: *{len([r for r in results if '🟡' in r])}*\n"
        f"🔴 З великою кількістю детектів: *{len([r for r in results if '🔴' in r])}*"
    )
    
    await progress_msg.edit_text(summary)
    await message.answer("Детальний звіт буде доступний в повній версії бота.", 
                         reply_markup=get_main_menu_keyboard())

# Обработка любого другого текста
@dp.message_handler()
async def handle_other_messages(message: types.Message):
    user_id = message.from_user.id
    text = message.text.strip()
    
    # Автоматическое распознавание API ключа
    if (user_id not in WAITING_API_KEY and 
        user_id not in WAITING_DOMAINS_ONETIME and
        (user_id not in user_data or not user_data[user_id].get('vt_api_key')) and
        len(text) == 64 and all(c in '0123456789abcdefABCDEF' for c in text)):
        
        # Сохраняем ключ
        if user_id not in user_data:
            user_data[user_id] = {}
        user_data[user_id]['vt_api_key'] = text
        
        await message.answer(
            "🔐 API-ключ *автоматично розпізнано і збережено* для твого акаунта!\n\n"
            "Тепер можеш користуватися разовою перевіркою доменів.",
            reply_markup=get_main_menu_keyboard()
        )
        return
    
    # Если текст не распознан
    await message.answer(
        "Не зовсім зрозумів, що ти маєш на увазі 🧐\n"
        "Скористайся кнопками нижче:",
        reply_markup=get_main_menu_keyboard()
    )

# Запуск бота
if __name__ == '__main__':
    logger.info("Бот запускается...")
    executor.start_polling(dp, skip_updates=True)
