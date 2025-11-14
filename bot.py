import os
import re
import time
import hashlib
import html
import threading
import asyncio
import logging
from datetime import datetime, timedelta

import requests
from bs4 import BeautifulSoup
import pycountry
import telegram
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from flask import Flask, Response
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    CallbackQueryHandler,
)

# -------------------------
# CONFIG (user provided)
# -------------------------
BOT_TOKEN = "8361669889:AAG1yhhuj-shI07BWRUBGzem-SfokBbQCX0"
CHAT_IDS = ["-1002822806611"]   # primary group
CHANNEL_LINK = "https://t.me/freeotpss"
ADMIN_ID = 7761576669
ADMIN_CHAT_ID = str(ADMIN_ID)

# Panel 1 (original from first bot)
P1 = {
    "name": "Panel-1",
    "login_url": "http://51.89.99.105/NumberPanel/signin",
    "login_page": "http://51.89.99.105/NumberPanel/login",
    "xhr_url": "http://51.89.99.105/NumberPanel/agent/res/data_smscdr.php?fdate1=2025-09-05%2000:00:00&fdate2=2026-09-04%2023:59:59&frange=&fclient=&fnum=&fcli=&fgdate=&fgmonth=&fgrange=&fgclient=&fgnumber=&fgcli=&fg=0&sEcho=1&iColumns=9&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=1&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&mDataProp_7=7&sSearch_7=&bRegex_7=false&bSearchable_7=true&bSortable_7=true&mDataProp_8=8&sSearch_8=&bRegex_8=false&bSearchable_8=true&bSortable_8=false&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=1756968295291",
    "username": "developer25",
    "password": "developer25",
    "headers": {
        "User-Agent": "Mozilla/5.0",
        "Referer": "http://51.89.99.105/NumberPanel/login"
    },
    "ajax_headers": {
        "User-Agent": "Mozilla/5.0",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "http://51.89.99.105/NumberPanel/agent/SMSCDRStats"
    }
}

# Panel 2 (original from second bot)
P2 = {
    "name": "Panel-2",
    "login_url": "http://51.83.103.80/ints/signin",
    "login_page": "http://51.83.103.80/ints/login",
    "xhr_url": "http://51.83.103.80/ints/agent/res/data_smscdr.php?fdate1=2025-09-05%2000:00:00&fdate2=2026-09-04%2023:59:59&frange=&fclient=&fnum=&fcli=&fgdate=&fgmonth=&fgrange=&fgclient=&fgnumber=&fgcli=&fg=0&sEcho=1&iColumns=9&sColumns=%2C%2C%2C%2C%2C%2C%2C%2C%2C&iDisplayStart=0&iDisplayLength=1&mDataProp_0=0&sSearch_0=&bRegex_0=false&bSearchable_0=true&bSortable_0=true&mDataProp_1=1&sSearch_1=&bRegex_1=false&bSearchable_1=true&bSortable_1=true&mDataProp_2=2&sSearch_2=&bRegex_2=false&bSearchable_2=true&bSortable_2=true&mDataProp_3=3&sSearch_3=&bRegex_3=false&bSearchable_3=true&bSortable_3=true&mDataProp_4=4&sSearch_4=&bRegex_4=false&bSearchable_4=true&bSortable_4=true&mDataProp_5=5&sSearch_5=&bRegex_5=false&bSearchable_5=true&bSortable_5=true&mDataProp_6=6&sSearch_6=&bRegex_6=false&bSearchable_6=true&bSortable_6=true&mDataProp_7=7&sSearch_7=&bRegex_7=false&bSearchable_7=true&bSortable_7=true&mDataProp_8=8&sSearch_8=&bRegex_8=false&bSearchable_8=true&bSortable_8=false&sSearch=&bRegex=false&iSortCol_0=0&sSortDir_0=desc&iSortingCols=1&_=1756968295291",
    "username": os.getenv("USERNAME", "h2ideveloper898"),
    "password": os.getenv("PASSWORD", "112233"),
    "headers": {
        "User-Agent": "Mozilla/5.0",
        "Referer": "http://51.83.103.80/ints/login"
    },
    "ajax_headers": {
        "User-Agent": "Mozilla/5.0",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": "http://51.83.103.80/ints/agent/SMSCDRStats"
    }
}

EXTRA_CODES = {"Kosovo": "XK"}

# -------------------------
# GLOBALS
# -------------------------
app = Flask(__name__)
bot = telegram.Bot(token=BOT_TOKEN)
session1 = requests.Session()
session2 = requests.Session()
seen = set()   # shared across both panels to avoid duplicates
lock = threading.Lock()

# -------------------------
# Logging - hacker green terminal style
# -------------------------
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
RESET = "\033[0m"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("merged-otp-bot")

# -------------------------
# Panel states & metrics
# -------------------------
panel_status = {
    "Panel-1": True,
    "Panel-2": True,
}
panel_start_time = { "Panel-1": datetime.now(), "Panel-2": datetime.now() }
failure_counter = { "Panel-1": 0, "Panel-2": 0 }   # track consecutive login failures
panel_otp_count = { "Panel-1": 0, "Panel-2": 0 }
last_otp_time = { "Panel-1": None, "Panel-2": None }

def tlog(msg, level="info"):
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    colored = f"{GREEN}[{now}] {msg}{RESET}"
    if level == "info":
        logger.info(colored)
    elif level == "warn":
        logger.warning(f"{YELLOW}{msg}{RESET}")
    elif level == "error":
        logger.error(f"{RED}{msg}{RESET}")
    else:
        logger.info(colored)

# -------------------------
# Utilities
# -------------------------
def is_admin(update: Update) -> bool:
    try:
        return update.effective_user.id == ADMIN_ID
    except Exception:
        return False

def send_admin_alert_async(text: str):
    """Fire-and-forget admin alert (thread)"""
    def _send():
        try:
            bot.send_message(chat_id=ADMIN_CHAT_ID, text=text)
            tlog(f"Admin alert sent: {text}")
        except Exception as e:
            tlog(f"Failed sending admin alert: {e}", level="warn")
    threading.Thread(target=_send, daemon=True).start()

def country_to_flag(country_name: str) -> str:
    code = EXTRA_CODES.get(country_name)
    if not code:
        try:
            country = pycountry.countries.lookup(country_name)
            code = country.alpha_2
        except LookupError:
            return ""
    return "".join(chr(127397 + ord(c)) for c in code.upper())

def mask_number(number):
    if not number:
        return ""
    number = str(number)
    if len(number) <= 6:
        return number
    mid = len(number) // 2
    return number[:mid-1] + "***" + number[mid+2:]

def extract_otp(message: str) -> str | None:
    if not message:
        return None
    message = message.strip()
    keyword_regex = re.search(r"(otp|code|pin|password)[^\d]{0,10}(\d[\d\-]{3,8})", message, re.I)
    if keyword_regex:
        return re.sub(r"\D", "", keyword_regex.group(2))
    reverse_regex = re.search(r"(\d[\d\-]{3,8})[^\w]{0,10}(otp|code|pin|password)", message, re.I)
    if reverse_regex:
        return re.sub(r"\D", "", reverse_regex.group(1))
    generic_regex = re.findall(r"\b\d[\d\-]{3,8}\b", message)
    for num in generic_regex:
        num_clean = re.sub(r"\D", "", num)
        if 4 <= len(num_clean) <= 8 and not (1900 <= int(num_clean) <= 2099):
            return num_clean
    return None

# -------------------------
# Telegram send (with flood detection + notification)
# -------------------------
async def send_telegram_message(source_label, current_time, country, number, sender, message):
    flag = country_to_flag(country)
    otp = extract_otp(message)

    otp_section = (
        f"\n🔐 <b>OTP:</b> <code>{html.escape(otp)}</code>\n"
        if otp else ""
    )

    formatted = (
        f"🚨 <b>New OTP Received!</b>\n"
        f"{flag} <b>{country}</b> | <b>{sender}</b>\n"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"📞 <b>Number:</b> <code>{html.escape(mask_number(number))}</code>\n"
        f"{otp_section}"
        f"━━━━━━━━━━━━━━━━━━━\n"
        f"💬 <b>Message:</b>\n"
        f"<code>{html.escape(message)}</code>\n"
        f"━━━━━━━━━━━━━━━━━━━"
    )

    keyboard = [
        [InlineKeyboardButton("📱 Visit Channel", url=CHANNEL_LINK)],
        [InlineKeyboardButton("👨‍💻 Contact Dev", url=f"https://t.me/{str(ADMIN_ID)}")]
    ]
    reply_markup = InlineKeyboardMarkup(keyboard)

    await asyncio.sleep(0.8)

    for chat_id in CHAT_IDS:
        try:
            await bot.send_message(
                chat_id=chat_id,
                text=formatted,
                reply_markup=reply_markup,
                disable_web_page_preview=True,
                parse_mode="HTML"
            )
            tlog(f"✅ Sent to {chat_id} [{sender}] from {source_label}: {mask_number(number)}")
            # metrics
            panel_otp_count.setdefault(source_label, 0)
            panel_otp_count[source_label] += 1
            last_otp_time[source_label] = datetime.now()
        except Exception as e:
    estr = str(e).lower()
    tlog(f"❌ Failed to send to {chat_id}: {e}", level="error")

    # ---------- NEW ADMIN ALERT FOR ACCESS PROBLEMS ----------
    if "kicked" in estr or "forbidden" in estr or "not enough rights" in estr:
        send_admin_alert_async(
            f"❌ ERROR while sending OTP\n"
            f"Chat ID: {chat_id}\n"
            f"Reason: {e}\n\n"
            f"⚠️ Bot removed OR no send rights — Fix group permissions!"
        )
    # ---------- END ----------
            # If flood control or RetryAfter detected, auto-pause that panel and notify admin
            if "retryafter" in estr or "too many requests" in estr or "flood" in estr:
                tlog(f"⚠️ Flood control detected for {source_label}. Auto-pausing panel.", level="warn")
                panel_status[source_label] = False
                send_admin_alert_async(f"⚠️ Flood control detected. {source_label} paused automatically.\nReason: {e}")
                # schedule resume after cooldown
                def resume_later(panel_name, delay=30):
                    time.sleep(delay)
                    panel_status[panel_name] = True
                    tlog(f"▶️ {panel_name} resumed after cooldown.")
                    send_admin_alert_async(f"▶️ {panel_name} auto-resumed after cooldown.")
                threading.Thread(target=resume_later, args=(source_label, 30), daemon=True).start()
            else:
                # try to alert admin for unknown errors
                send_admin_alert_async(f"❌ Failed to send OTP to group {chat_id} from {source_label}\nError: {e}")

# -------------------------
# Panel login handlers (with failure counter)
# -------------------------
def solve_captcha_and_login(session: requests.Session, panel: dict) -> bool:
    try:
        res = session.get(panel["login_page"], headers=panel["headers"], timeout=12)
        soup = BeautifulSoup(res.text, "html.parser")
        captcha_text = next((s.strip() for s in soup.stripped_strings if "What is" in s and "+" in s), None)

        if not captcha_text:
            tlog(f"[{panel['name']}] Captcha not found when GETting login page.", level="error")
            return False

        m = re.search(r"What is\s*(\d+)\s*\+\s*(\d+)", captcha_text)
        if not m:
            tlog(f"[{panel['name']}] Captcha format unexpected.", level="error")
            return False

        a, b = int(m.group(1)), int(m.group(2))
        capt = str(a + b)
        payload = {"username": panel.get("username"), "password": panel.get("password"), "capt": capt}
        r = session.post(panel["login_url"], data=payload, headers=panel["headers"], timeout=12)
        if "SMSCDRStats" in r.text or r.status_code == 200:
            # reset failure counter
            failure_counter[panel["name"]] = 0
            panel_start_time.setdefault(panel["name"], datetime.now())
            tlog(f"[{panel['name']}] Logged in successfully.")
            return True
        failure_counter[panel["name"]] = failure_counter.get(panel["name"], 0) + 1
        tlog(f"[{panel['name']}] Login failed (attempt #{failure_counter[panel['name']]}).", level="error")
        # auto-pause & notify after 3 consecutive failures
        if failure_counter[panel["name"]] >= 3:
            panel_status[panel["name"]] = False
            send_admin_alert_async(f"⚠️ {panel['name']} auto-paused after {failure_counter[panel['name']]} failed login attempts.")
        return False
    except Exception as e:
        failure_counter[panel["name"]] = failure_counter.get(panel["name"], 0) + 1
        tlog(f"[{panel['name']}] Login exception: {e}", level="error")
        if failure_counter[panel["name"]] >= 3:
            panel_status[panel["name"]] = False
            send_admin_alert_async(f"⚠️ {panel['name']} auto-paused after {failure_counter[panel['name']]} login exceptions.")
        return False

# -------------------------
# Fetch loops (one per panel)
# -------------------------
def panel_fetch_loop(panel: dict, session: requests.Session):
    name = panel["name"]
    tlog(f"🔄 Starting fetch loop for {name} ...")

    # each thread its own loop
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # initial login
    if not solve_captcha_and_login(session, panel):
        tlog(f"⚠️ Could not login to {name}. Will retry in 10s.", level="warn")
        time.sleep(10)

    while True:
        try:
            # check on/off state
            if not panel_status.get(name, True):
                tlog(f"⏸ {name} paused — sleeping 5s", level="warn")
                time.sleep(5)
                continue

            res = session.get(panel["xhr_url"], headers=panel["ajax_headers"], timeout=15)
            data = res.json() if res.status_code == 200 else {}
            otps = [row for row in data.get("aaData", []) if isinstance(row[0], str) and ":" in row[0]]

            for row in otps:
                try:
                    time_ = row[0]
                    operator = row[1].split("-")[0] if row[1] else ""
                    number = row[2] if len(row) > 2 else ""
                    sender = row[3] if len(row) > 3 else ""
                    message = row[5] if len(row) > 5 else ""
                    hash_id = hashlib.md5((str(number) + str(time_) + str(message)).encode()).hexdigest()

                    with lock:
                        if hash_id in seen:
                            continue
                        seen.add(hash_id)

                    tlog(f"[{name}] New: {mask_number(number)} — {sender}")
                    # send (run in this thread loop)
                    loop.run_until_complete(
                        send_telegram_message(name, time_, operator, number, sender, message)
                    )

                except Exception as inner_e:
                    tlog(f"[{name}] Error processing row: {inner_e}", level="error")

        except Exception as e:
            tlog(f"[{name}] Fetch error: {e}", level="error")
            tlog(f"[{name}] Attempting relogin in 5s...", level="warn")
            time.sleep(5)
            solve_captcha_and_login(session, panel)

        time.sleep(1.2)

# -------------------------
# Telegram commands & listener
# -------------------------
# -------------------------
# ✅ Admin-only access checker
# -------------------------
async def admin_only(update, context):
    """Return True if user is admin, else deny access."""
    user_id = update.effective_user.id
    if user_id != ADMIN_ID:
        await update.message.reply_text("❌ You are not authorized to use this command.")
        return False
    return True

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🤖 <b>H2I Number Bot</b>\n",
        parse_mode="HTML",
        disable_web_page_preview=True
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):  # check admin
        return

    help_text = (
        "📘 <b>Available Commands</b>\n"
        "━━━━━━━━━━━━━━━━━━━\n"
        "🤖 <b>General</b>\n"
        "/start - Show bot info\n"
        "/help - Display this help menu\n"
        "/status - Show panel statuses and OTP counts\n\n"
        "🧠 <b>Panel Control</b>\n"
        "/panel &lt;Panel-Name&gt; on|off - Enable or disable a specific panel\n"
        "/pauseall - Pause all panels\n"
        "/resumeall - Resume all panels\n"
        "/control - Inline buttons to pause/resume panels\n\n"
        "⚙️ <b>Admin Tools</b>\n"
        "/addchat &lt;chat_id&gt; - Add group for OTP delivery\n"
        "/removechat &lt;chat_id&gt; - Remove group from list\n\n"
        "📢 <b>Notifications</b>\n"
        "🔔 Alerts for:\n"
        "• Panel auto-paused after 3 failed logins\n"
        "• Flood control active\n"
        "• Auto-resume after cooldown\n"
    )
    await update.message.reply_text(help_text, parse_mode="HTML", disable_web_page_preview=True)

async def status_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):
        return

    status_lines = ["🧩 <b>Panel Status</b>\n━━━━━━━━━━━━━━━━━━━"]
    for panel_name, is_active in panel_status.items():
        emoji = "✅ Running" if is_active else "⏸ Paused"
        status_lines.append(f"{panel_name}: {emoji}")
    status_text = "\n".join(status_lines)
    await update.message.reply_text(status_text, parse_mode="HTML")

async def toggle_panel(update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):
        return
    if len(context.args) < 2:
        return await update.message.reply_text("Usage: /panel <Panel-Name> on|off")

    name, action = context.args[0], context.args[1].lower()
    if name not in panel_status:
        return await update.message.reply_text(f"⚠️ Unknown panel: {name}")
    if action not in ["on", "off"]:
        return await update.message.reply_text("⚙️ Use 'on' or 'off' only")

    panel_status[name] = (action == "on")
    status_text = "▶️ resumed" if action == "on" else "⏸ paused"
    await update.message.reply_text(f"✅ {name} {status_text}.")
    tlog(f"{name} {status_text} via Telegram command.")

async def pauseall_command(update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):
        return

    for k in panel_status.keys():
        panel_status[k] = False
    await update.message.reply_text("⏸ All panels paused.")
    tlog("All panels paused by admin.")


async def resumeall_command(update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):
        return

    for k in panel_status.keys():
        panel_status[k] = True
    await update.message.reply_text("▶️ All panels resumed.")
    tlog("All panels resumed by admin.")

async def add_chat(update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):
        return
    if not context.args:
        return await update.message.reply_text("Usage: /addchat <chat_id>")
    chat_id = context.args[0]
    if chat_id not in CHAT_IDS:
        CHAT_IDS.append(chat_id)
        await update.message.reply_text(f"✅ Chat ID {chat_id} added.")
    else:
        await update.message.reply_text("⚠️ Already present.")


async def remove_chat(update, context: ContextTypes.DEFAULT_TYPE):
    if not await admin_only(update, context):
        return
    if not context.args:
        return await update.message.reply_text("Usage: /removechat <chat_id>")
    chat_id = context.args[0]
    if chat_id in CHAT_IDS:
        CHAT_IDS.remove(chat_id)
        await update.message.reply_text(f"✅ Chat ID {chat_id} removed.")
    else:
        await update.message.reply_text("⚠️ Not found.")

# Inline control: send a menu with buttons for each panel
async def control_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not is_admin(update):
        return await update.message.reply_text("❌ Only admin can use the control panel.")
    buttons = []
    for pname in panel_status.keys():
        label = "▶️ Resume" if not panel_status[pname] else "⏸ Pause"
        buttons.append([InlineKeyboardButton(f"{pname}: {label}", callback_data=f"toggle:{pname}")])
    reply_markup = InlineKeyboardMarkup(buttons)
    await update.message.reply_text("Panel Control:", reply_markup=reply_markup)

# Callback handler for inline buttons
async def callback_toggle(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    user = update.effective_user
    if user.id != ADMIN_ID:
        return await query.edit_message_text("❌ Only admin can control panels.")
    data = query.data or ""
    if data.startswith("toggle:"):
        pname = data.split(":", 1)[1]
        if pname in panel_status:
            panel_status[pname] = not panel_status[pname]
            status_text = "resumed" if panel_status[pname] else "paused"
            tlog(f"{pname} {status_text} via inline button.")
            await query.edit_message_text(f"{pname} is now {status_text}.")
        else:
            await query.edit_message_text("Panel not found.")

def start_telegram_listener():
    tlog("🚀 Starting Telegram listener...")
    tg_app = Application.builder().token(BOT_TOKEN).build()
    tg_app.add_handler(CommandHandler("start", start_command))
    tg_app.add_handler(CommandHandler("help", help_command))
    tg_app.add_handler(CommandHandler("status", status_command))
    tg_app.add_handler(CommandHandler("panel", toggle_panel))
    tg_app.add_handler(CommandHandler("pauseall", pauseall_command))
    tg_app.add_handler(CommandHandler("resumeall", resumeall_command))
    tg_app.add_handler(CommandHandler("addchat", add_chat))
    tg_app.add_handler(CommandHandler("removechat", remove_chat))
    tg_app.add_handler(CommandHandler("control", control_cmd))
    tg_app.add_handler(CallbackQueryHandler(callback_toggle))
    tg_app.run_polling()

# -------------------------
# Flask endpoints
# -------------------------
@app.route('/health')
def health():
    return Response("OK", status=200)

@app.route('/')
def root():
    return Response("Merged OTP Bot is running", status=200)

@app.route('/panel/<name>/<action>')
def panel_control(name, action):
    if name not in panel_status:
        return Response("Panel not found", status=404)

    if action.lower() == "on":
        panel_status[name] = True
        panel_start_time.setdefault(name, datetime.now())
        tlog(f"▶️ {name} resumed via API.")
        return Response(f"{name} resumed", status=200)
    elif action.lower() == "off":
        panel_status[name] = False
        tlog(f"⏸ {name} paused via API.")
        return Response(f"{name} paused", status=200)
    else:
        return Response("Use on/off", status=400)

# -------------------------
# Main start
# -------------------------
def main():
    tlog("Starting merged bot v4...", level="info")
    # start fetch threads for both panels
    t1 = threading.Thread(target=panel_fetch_loop, args=(P1, session1), daemon=True)
    t2 = threading.Thread(target=panel_fetch_loop, args=(P2, session2), daemon=True)
    t1.start()
    t2.start()

    # start flask in background (use 8081 to avoid conflicts)
    flask_thread = threading.Thread(target=lambda: app.run(host='0.0.0.0', port=8081), daemon=True)
    flask_thread.start()

    # start telegram listener (blocking)
    start_telegram_listener()

if __name__ == "__main__":
    main()
