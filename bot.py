import os
import logging
from aiogram import Bot, Dispatcher, types, executor
from aiogram.types import InlineKeyboardMarkup, InlineKeyboardButton

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Получение токена
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN не задан")

# Инициализация
bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

# Временное хранилище (для теста)
user_storage = {}

def get_main_menu():
    keyboard = InlineKeyboardMarkup(row_width=1)
    keyboard.add(
        InlineKeyboardButton("✅ Тест кнопка 1", callback_data="test_1"),
        InlineKeyboardButton("🔐 Тест кнопка 2", callback_data="test_2"),
        InlineKeyboardButton("ℹ️ Тест кнопка 3", callback_data="test_3")
    )
    return keyboard

@dp.message_handler(commands=['start', 'test'])
async def start_command(message: types.Message):
    logger.info(f"User {message.from_user.id} started bot")
    await message.answer(
        "🚀 <b>Тестовый бот</b>\n\n"
        "Проверка работы кнопок. Нажми любую кнопку:",
        reply_markup=get_main_menu(),
        parse_mode="HTML"
    )

# ОБРАБОТЧИКИ CALLBACK - ВАЖНО!
@dp.callback_query_handler(lambda c: c.data == "test_1")
async def test_callback_1(callback: types.CallbackQuery):
    user_id = callback.from_user.id
    logger.info(f"Callback test_1 от пользователя {user_id}")
    
    # ОБЯЗАТЕЛЬНО отвечаем на callback
    await callback.answer("✅ Кнопка 1 сработала!", show_alert=False)
    
    # Редактируем сообщение или отправляем новое
    await callback.message.edit_text(
        f"🎉 <b>Кнопка 1 работает!</b>\n\n"
        f"User ID: {user_id}\n"
        f"Время: {callback.message.date}",
        reply_markup=get_main_menu(),
        parse_mode="HTML"
    )

@dp.callback_query_handler(lambda c: c.data == "test_2")
async def test_callback_2(callback: types.CallbackQuery):
    logger.info(f"Callback test_2 от пользователя {callback.from_user.id}")
    await callback.answer("✅ Кнопка 2 сработала!", show_alert=False)
    
    await callback.message.answer(
        "🔐 <b>Кнопка 2 активирована</b>\n\n"
        "Эта кнопка отправляет новое сообщение вместо редактирования старого.",
        parse_mode="HTML"
    )

@dp.callback_query_handler(lambda c: c.data == "test_3")
async def test_callback_3(callback: types.CallbackQuery):
    logger.info(f"Callback test_3 от пользователя {callback.from_user.id}")
    await callback.answer("📢 Это всплывающее уведомление!", show_alert=True)
    
    await callback.message.edit_text(
        "ℹ️ <b>Кнопка 3 сработала</b>\n\n"
        "Вы увидели всплывающее уведомление, а сообщение было отредактировано.",
        reply_markup=get_main_menu(),
        parse_mode="HTML"
    )

# Обработчик любых сообщений
@dp.message_handler()
async def echo_message(message: types.Message):
    await message.answer(
        "Отправьте /start для теста кнопок\n"
        "Или /test для перезагрузки меню"
    )

if __name__ == '__main__':
    logger.info("=== ЗАПУСК ТЕСТОВОГО БОТА ===")
    logger.info("Режим: polling")
    logger.info("Бот должен работать на Railway с polling")
    
    # Запускаем polling
    executor.start_polling(
        dp, 
        skip_updates=True,
        timeout=60,
        relax=0.1
    )
