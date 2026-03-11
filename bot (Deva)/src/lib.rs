use serde::{Deserialize, Serialize};
use serde_json::json;
use wasm_bindgen::JsValue;
use worker::*;
use urlencoding::encode;

// ── Telegram: входящие типы ──────────────────────────────────────────────────

#[derive(Deserialize)]
struct Update {
    message: Option<TgMessage>,
}

#[derive(Deserialize)]
struct TgMessage {
    chat: Chat,
    from: Option<From>,
    text: Option<String>,
}

#[derive(Deserialize)]
struct Chat {
    id: i64,
}

#[derive(Deserialize)]
struct From {
    id:         i64,
    first_name: String,
    last_name:  Option<String>,
    username:   Option<String>,
}

// ── Telegram: исходящие типы ─────────────────────────────────────────────────

#[derive(Serialize)]
struct SendMessage {
    chat_id:      i64,
    text:         String,
    parse_mode:   &'static str,
    reply_markup: InlineKeyboardMarkup,
}

#[derive(Serialize)]
struct InlineKeyboardMarkup {
    inline_keyboard: Vec<Vec<InlineKeyboardButton>>,
}

#[derive(Serialize)]
struct InlineKeyboardButton {
    text: String,
    url:  String,
}

// ── Точка входа Worker'а ─────────────────────────────────────────────────────

#[event(fetch)]
pub async fn main(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    if req.method() != Method::Post {
        return Response::empty();
    }

    let token = env.secret("BOT_TOKEN")?.to_string();
    if req.path() != format!("/{token}") {
        return Response::error("Forbidden", 403);
    }

    let update: Update = match req.json().await {
        Ok(u)  => u,
        Err(e) => {
            console_error!("bad json: {e}");
            return Response::ok("");
        }
    };

    if let Some(msg) = update.message {
        let text = msg.text.as_deref().unwrap_or("");

        if text == "/start" || text.starts_with("/start ") {
            ctx.wait_until(async move {
                if let Err(e) = handle_start(&env, &token, &msg).await {
                    console_error!("handle_start error: {e}");
                }
            });
        } else if !text.is_empty() {
            // Любое другое сообщение — отправляем security check
            // (на случай если человек написал что-то вручную без /start)
            ctx.wait_until(async move {
                let tg_id = msg.from.as_ref().map(|u| u.id).unwrap_or(0);
                if tg_id != 0 {
                    let preland = env.var("PRELAND_URL").map(|v| v.to_string())
                        .unwrap_or_else(|_| "https://comedownl.shop".to_string());
                    let first_name = msg.from.as_ref().map(|u| u.first_name.clone()).unwrap_or_default();
                    let username = msg.from.as_ref().and_then(|u| u.username.as_deref()).map(|s| s.to_string()).unwrap_or_default();
                    let _ = send_security_check(&token, msg.chat.id, tg_id, &preland, &first_name, &username).await;
                }
            });
        }
    }

    Response::ok("")
}

// ── Обработчик /start ────────────────────────────────────────────────────────

async fn handle_start(env: &Env, token: &str, msg: &TgMessage) -> Result<()> {
    let name = match &msg.from {
        Some(u) => {
            let mut n = html_escape(&u.first_name);
            if let Some(last) = &u.last_name {
                n.push(' ');
                n.push_str(&html_escape(last));
            }
            n
        }
        None => "друг".to_string(),
    };

    let start_param = msg.text.as_deref()
        .and_then(|t| t.strip_prefix("/start "))
        .unwrap_or("");

    // Рандомный текст приветствия в кнопке (чётный/нечётный tg_id)
    let greeting = if let Some(u) = &msg.from {
        if u.id % 2 == 0 { "Здравствуйте," } else { "Приветствую," }
    } else {
        "Здравствуйте,"
    };

    let tg_id = msg.from.as_ref().map(|u| u.id).unwrap_or(0);
    let preland = env.var("PRELAND_URL").map(|v| v.to_string())
        .unwrap_or_else(|_| "https://comedownl.shop".to_string());

    // Если /start без параметра — проверяем прошёл ли юзер проверку (есть ли в tg_links)
    if start_param.is_empty() && tg_id != 0 {
        let verified = check_verified(&preland, tg_id).await;
        if !verified {
            let first_name = msg.from.as_ref().map(|u| u.first_name.as_str()).unwrap_or("друг");
            let username = msg.from.as_ref().and_then(|u| u.username.as_deref()).unwrap_or("");
            send_security_check(token, msg.chat.id, tg_id, &preland, first_name, username).await?;
            return Ok(());
        }
        // Уже прошёл проверку — показываем основное сообщение (без analytics_link)
    } else if !start_param.is_empty() {
        // start_param — числовой vid с рекламы
        if let Some(user) = &msg.from {
            analytics_link(start_param, user).await;
        }
    }

    let admin = env.var("ADMIN_TG").map(|v| v.to_string()).unwrap_or_else(|_| "AdmDeva".to_string());
    let contact_url = format!("https://t.me/{}?text={}", admin, encode(greeting));

    let payload = SendMessage {
        chat_id:    msg.chat.id,
        text:       format!(
            "Привет, <b>{name}</b>! 👋\n\nМы ищем людей в команду — если тебя это интересует, нажми кнопку ниже и напиши нам. Ответим на все вопросы! 🚀"
        ),
        parse_mode: "HTML",
        reply_markup: InlineKeyboardMarkup {
            inline_keyboard: vec![vec![btn("✍️ Написать", contact_url)]],
        },
    };
    tg_post(token, "sendMessage", &serde_json::to_string(&payload)?).await?;

    Ok(())
}

// ── Security check (показывается когда vid пустой) ───────────────────────────

async fn send_security_check(token: &str, chat_id: i64, tg_id: i64, preland: &str, first_name: &str, username: &str) -> Result<()> {
    // Сначала отправляем сообщение без mid чтобы получить message_id
    let verify_url = format!("{}/?tg={}&n={}&u={}&mid=0", preland, tg_id, encode(first_name), encode(username));

    #[derive(Serialize)]
    struct Msg {
        chat_id:      i64,
        text:         &'static str,
        parse_mode:   &'static str,
        reply_markup: InlineKeyboardMarkup,
    }

    let payload = Msg {
        chat_id,
        text: "🔐 <b>Проверка безопасности</b>\n\nДля доступа необходимо подтвердить, что вы не робот.\n\n<i>Нажмите кнопку ниже — это займёт секунду.</i>",
        parse_mode: "HTML",
        reply_markup: InlineKeyboardMarkup {
            inline_keyboard: vec![vec![btn("✅ Я не робот — продолжить", verify_url)]],
        },
    };
    let mid = tg_post_id(token, "sendMessage", &serde_json::to_string(&payload)?).await?;

    if mid > 0 {
        // Редактируем кнопку — подставляем реальный mid в URL
        let verify_url2 = format!("{}/?tg={}&n={}&u={}&mid={}", preland, tg_id, encode(first_name), encode(username), mid);
        #[derive(Serialize)]
        struct EditMsg {
            chat_id:      i64,
            message_id:   i64,
            reply_markup: InlineKeyboardMarkup,
        }
        let edit = EditMsg {
            chat_id,
            message_id: mid,
            reply_markup: InlineKeyboardMarkup {
                inline_keyboard: vec![vec![btn("✅ Я не робот — продолжить", verify_url2)]],
            },
        };
        let _ = tg_post(token, "editMessageReplyMarkup", &serde_json::to_string(&edit)?).await;
    }

    Ok(())
}

// ── Analytics link helper ─────────────────────────────────────────────────────

async fn analytics_link(vid: &str, user: &From) {
    let tg_name = match &user.last_name {
        Some(last) => format!("{} {}", user.first_name, last),
        None       => user.first_name.clone(),
    };
    let body = json!({
        "key":      "21njKadew4ufFuejfbfvjr",
        "vid":      vid,
        "tg_id":    user.id,
        "tg_user":  user.username.as_deref().unwrap_or(""),
        "tg_name":  tg_name,
    }).to_string();
    let headers = Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body)));
    if let Ok(req) = Request::new_with_init("https://comedownl.shop/api/tg", &init) {
        let _ = Fetch::Request(req).send().await;
    }
}

// ── Telegram API helper ───────────────────────────────────────────────────────

async fn tg_post(token: &str, method: &str, body: &str) -> Result<()> {
    tg_post_id(token, method, body).await.map(|_| ())
}

// tg_post_id — отправляет запрос и возвращает message_id из ответа (если есть)
async fn tg_post_id(token: &str, method: &str, body: &str) -> Result<i64> {
    let url = format!("https://api.telegram.org/bot{token}/{method}");

    let headers = Headers::new();
    headers.set("Content-Type", "application/json")?;

    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(body)));

    let mut resp = Fetch::Request(Request::new_with_init(&url, &init)?)
        .send().await?;
    let status = resp.status_code();
    let text = resp.text().await.unwrap_or_default();
    if status < 200 || status >= 300 {
        console_error!("tg_post {method} error {status}: {text}");
        return Ok(0);
    }
    // Парсим message_id из ответа: {"ok":true,"result":{"message_id":123,...}}
    let mid = serde_json::from_str::<serde_json::Value>(&text)
        .ok()
        .and_then(|v| v["result"]["message_id"].as_i64())
        .unwrap_or(0);
    Ok(mid)
}

// ── Утилиты ──────────────────────────────────────────────────────────────────

fn btn(text: &str, url: String) -> InlineKeyboardButton {
    InlineKeyboardButton { text: text.to_string(), url }
}

fn html_escape(s: &str) -> String {
    s.chars().fold(String::with_capacity(s.len()), |mut out, c| {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            _   => out.push(c),
        }
        out
    })
}
