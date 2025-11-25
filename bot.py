import os
import logging
from aiogram import Bot, Dispatcher, types, executor

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN не задан")

bot = Bot(token=BOT_TOKEN)
dp = Dispatcher(bot)

def get_menu():
    return types.InlineKeyboardMarkup().add(
        types.InlineKeyboardButton("Тест кнопка", callback_data="test_button")
    )

@dp.message_handler(commands=['start'])
async def start(msg: types.Message):
    await msg.answer("Тест бота. Нажми кнопку:", reply_markup=get_menu())

@dp.callback_query_handler(text="test_button")
async def test_callback(callback: types.CallbackQuery):
    logger.info("Кнопка нажата!")
    await callback.answer("Кнопка работает! ✅", show_alert=True)
    await callback.message.answer("✅ Кнопка сработала успешно!")

if __name__ == '__main__':
    logger.info("Запускаем простой тест...")
    executor.start_polling(dp, skip_updates=True)
