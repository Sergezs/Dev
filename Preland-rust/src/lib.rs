use worker::*;
use serde::{Deserialize, Serialize, Deserializer};
use sha2::Sha256;
use hmac::{Hmac, Mac};
type HmacSha256 = Hmac<Sha256>;
use std::collections::HashMap;
use wasm_bindgen::JsValue;

// ── Константы (Constants) ─────────────────────────────────────────────────────
// Секретный ключ для API запросов к /api/stats, /api/purchase, /api/tg
// Соль для хэширования IP адресов (чтобы не хранить реальные IP)
// Логин и пароль для входа в дашборд /analytics — хранятся в секретах Cloudflare (DASH_LOGIN, DASH_PASS)

// ── Вспомогательные парсеры (Helper parsers) ──────────────────────────────────

// parse_time — парсит время из JSON (принимает число или строку)
fn parse_time<'de, D>(d: D) -> Result<i64, D::Error> where D: Deserializer<'de> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V { I(i64), U(u64), S(String) }
    match V::deserialize(d)? {
        V::I(i) => Ok(i),
        V::U(u) => Ok(u as i64),
        V::S(s) => Ok(s.parse().unwrap_or(0)),
    }
}

// parse_f64 — парсит число с плавающей точкой из JSON (принимает число или строку)
fn parse_f64<'de, D>(d: D) -> Result<f64, D::Error> where D: Deserializer<'de> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum V { F(f64), I(i64), U(u64), S(String) }
    match V::deserialize(d)? {
        V::F(f) => Ok(f),
        V::I(i) => Ok(i as f64),
        V::U(u) => Ok(u as f64),
        V::S(s) => Ok(s.parse().unwrap_or(0.0)),
    }
}

// ── Структуры данных (Data structures) ───────────────────────────────────────

// Visit — один визит на сайт (запись в таблице visits)
// t=время, h=хэш IP, co=страна, ci=город, d=устройство,
// s=источник, rf=referer, fbclid=ID клика ФБ, utm_c=кампания, vid=уникальный ID визита
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct Visit {
    #[serde(default)]
    id: i64,
    #[serde(default, deserialize_with = "parse_time")]
    t: i64,
    #[serde(default)]
    h: String,
    #[serde(default)]
    co: String,
    #[serde(default)]
    ci: String,
    #[serde(default)]
    d: String,
    #[serde(default)]
    s: String,
    #[serde(default)]
    rf: String,
    #[serde(default)]
    fbclid: String,
    #[serde(default)]
    utm_c: String,
    #[serde(default)]
    utm_ct: String,
    #[serde(default)]
    utm_as: String,
    #[serde(default)]
    ua: String,
    #[serde(default)]
    vid: String,
}

// Purchase — одна покупка (запись в таблице purchases)
// t=время, fbclid=ID клика ФБ, amount=сумма, currency=валюта,
// event_id=уникальный ID для дедупликации CAPI, capi_ok=отправлено ли в ФБ
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct Purchase {
    #[serde(default)]
    id: i64,
    #[serde(default, deserialize_with = "parse_time")]
    t: i64,
    #[serde(default)]
    fbclid: String,
    #[serde(default, deserialize_with = "parse_f64")]
    amount: f64,
    #[serde(default)]
    currency: String,
    #[serde(default, deserialize_with = "parse_time")]
    visit_t: i64,
    #[serde(default)]
    ua: String,
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    capi_ok: bool,
    #[serde(default)]
    utm_c: String,
}

// PurchaseReq — входящий JSON запрос на /api/purchase (из дашборда при нажатии Sale)
#[derive(Deserialize)]
struct PurchaseReq {
    key: String,
    fbclid: String,
    #[serde(default, deserialize_with = "parse_f64")]
    amount: f64,
    #[serde(default)]
    currency: String,
    #[serde(default, deserialize_with = "parse_time")]
    visit_t: i64,
    #[serde(default)]
    ua: String,
    #[serde(default)]
    utm_c: String,
}

// RegReq — входящий JSON запрос на /api/registration (из дашборда при нажатии Reg)
#[derive(Deserialize)]
struct RegReq {
    key: String,
    fbclid: String,
    #[serde(default, deserialize_with = "parse_time")]
    visit_t: i64,
    #[serde(default)]
    ua: String,
    #[serde(default)]
    utm_c: String,
}

// Registration — одна регистрация (запись в таблице registrations)
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct Registration {
    #[serde(default, deserialize_with = "parse_time")]
    t: i64,
    #[serde(default)]
    fbclid: String,
    #[serde(default, deserialize_with = "parse_time")]
    visit_t: i64,
    #[serde(default)]
    ua: String,
    #[serde(default)]
    event_id: String,
    #[serde(default)]
    capi_ok: bool,
    #[serde(default)]
    utm_c: String,
}

// TgLink — связка визита с телеграм пользователем (запись в таблице tg_links)
// vid=ID визита, tg_id=ID в телеграме, tg_user=username, tg_name=имя
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct TgLink {
    #[serde(default)]
    id: i64,
    #[serde(default, deserialize_with = "parse_time")]
    t: i64,
    #[serde(default)]
    vid: String,
    #[serde(default, deserialize_with = "parse_time")]
    tg_id: i64,
    #[serde(default)]
    tg_user: String,
    #[serde(default)]
    tg_name: String,
}

// TgReq — входящий JSON запрос на /api/tg (из бота когда пользователь написал /start)
#[derive(Deserialize)]
struct TgReq {
    key: String,
    vid: String,
    #[serde(default, deserialize_with = "parse_time")]
    tg_id: i64,
    #[serde(default)]
    tg_user: String,
    #[serde(default)]
    tg_name: String,
}

// Stats — статистика для дашборда (total визитов, покупок, выручка, топ стран/устройств/источников)
#[derive(Serialize)]
struct Stats {
    total: usize,
    purchases: usize,
    revenue: f64,
    countries: HashMap<String, usize>,
    devices: HashMap<String, usize>,
    sources: HashMap<String, usize>,
}

// ApiResp — ответ /api/stats (всё что нужно дашборду)
#[derive(Serialize)]
struct ApiResp {
    stats: Stats,
    visits: Vec<Visit>,
    purchases: Vec<Purchase>,
    registrations: Vec<Registration>,
    tg_links: Vec<TgLink>,
}

// ── Утилиты (Utilities) ───────────────────────────────────────────────────────

// hash_ip — хэширует IP + соль через SHA256, берёт первые 8 байт
fn hash_ip(ip: &str, salt: &str) -> String {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(ip);
    h.update(salt);
    hex::encode(&h.finalize()[..8])
}

// verify_webapp_init_data — проверяет подпись initData от Telegram Mini App
fn verify_webapp_init_data(init_data: &str, bot_token: &str) -> bool {
    // Парсим hash из initData
    let hash = init_data.split('&').find_map(|part| {
        part.strip_prefix("hash=").map(|v| v.to_string())
    }).unwrap_or_default();
    if hash.is_empty() { return false; }

    // Собираем data_check_string — все поля кроме hash, отсортированные, через 

    let mut parts: Vec<&str> = init_data.split('&')
        .filter(|p| !p.starts_with("hash="))
        .collect();
    parts.sort();
    let data_check_string = parts.join("
");

    // HMAC-SHA256(data_check_string, HMAC-SHA256("WebAppData", bot_token))
    let mut mac1 = HmacSha256::new_from_slice(b"WebAppData").unwrap();
    mac1.update(bot_token.as_bytes());
    let secret_key = mac1.finalize().into_bytes();

    let mut mac2 = HmacSha256::new_from_slice(&secret_key).unwrap();
    mac2.update(data_check_string.as_bytes());
    let expected = hex::encode(mac2.finalize().into_bytes());

    expected == hash
}

// parse_tg_user_from_init_data — извлекает username и имя из initData
fn parse_tg_user_from_init_data(init_data: &str) -> (String, String) {
    let user_str = init_data.split('&').find_map(|part| {
        part.strip_prefix("user=").map(|v| v.to_string())
    }).unwrap_or_default();
    if user_str.is_empty() { return (String::new(), String::new()); }
    let decoded = urlencoding::decode(&user_str).unwrap_or_default();
    let val = serde_json::from_str::<serde_json::Value>(&decoded).unwrap_or_default();
    let username = val["username"].as_str().unwrap_or("").to_string();
    let first = val["first_name"].as_str().unwrap_or("").to_string();
    let last = val["last_name"].as_str().unwrap_or("").to_string();
    let full_name = if last.is_empty() { first } else { format!("{} {}", first, last) };
    (username, full_name)
}

// parse_tg_id_from_init_data — извлекает tg_id из поля user в initData
fn parse_tg_id_from_init_data(init_data: &str) -> i64 {
    let user_str = init_data.split('&').find_map(|part| {
        part.strip_prefix("user=").map(|v| v.to_string())
    }).unwrap_or_default();
    if user_str.is_empty() { return 0; }
    // URL decode
    let decoded = urlencoding::decode(&user_str).unwrap_or_default();
    serde_json::from_str::<serde_json::Value>(&decoded)
        .ok()
        .and_then(|v| v["id"].as_i64())
        .unwrap_or(0)
}



// hdr — читает заголовок HTTP запроса по имени (возвращает пустую строку если нет)
fn hdr(h: &Headers, k: &str) -> String {
    h.get(k).ok().flatten().unwrap_or_default()
}

// rand_hex — генерирует случайную строку из n байт в hex формате
// Используется для event_id (дедупликация ФБ) и vid (уникальный ID визита)
fn rand_hex(n: usize) -> String {
    let mut buf = vec![0u8; n];
    let _ = getrandom::getrandom(&mut buf);
    hex::encode(buf)
}

// device — определяет тип устройства по User-Agent строке браузера
// Различает: TikTok/Instagram/FB браузеры, iPhone, Android, iPad, Mac, Windows, Linux
fn device(ua: &str) -> String {
    let u = ua.to_lowercase();
    if u.contains("tiktok") || u.contains("bytedance") {
        if u.contains("iphone") { return "📱 iPhone TikTok".into() }
        if u.contains("android") { return "📱 Android TikTok".into() }
        return "📱 TikTok".into()
    }
    if u.contains("instagram") {
        if u.contains("iphone") { return "📱 iPhone Insta".into() }
        if u.contains("android") { return "📱 Android Insta".into() }
        return "📱 Instagram".into()
    }
    if u.contains("fban") || u.contains("fbav") || u.contains("fb_iab") || u.contains("fb4a") {
        if u.contains("iphone") { return "📱 iPhone FB".into() }
        if u.contains("android") { return "📱 Android FB".into() }
        return "📱 Facebook".into()
    }
    if u.contains("fblite") || u.contains("fb lite") {
        if u.contains("iphone") { return "📱 iPhone FB Lite".into() }
        if u.contains("android") { return "📱 Android FB Lite".into() }
        return "📱 FB Lite".into()
    }
    if u.contains("messenger") || u.contains("fmessenger") {
        if u.contains("iphone") { return "📱 iPhone Messenger".into() }
        if u.contains("android") { return "📱 Android Messenger".into() }
        return "📱 Messenger".into()
    }
    if u.contains("audiencenetwork") || u.contains("audience_network") {
        if u.contains("iphone") { return "📱 iPhone Audience Net".into() }
        if u.contains("android") { return "📱 Android Audience Net".into() }
        return "📱 Audience Network".into()
    }
    if u.contains("threads") {
        if u.contains("iphone") { return "📱 iPhone Threads".into() }
        if u.contains("android") { return "📱 Android Threads".into() }
        return "📱 Threads".into()
    }
    if u.contains("iphone") { return "📱 iPhone".into() }
    if u.contains("ipad") { return "📱 iPad".into() }
    if u.contains("android") {
        if u.contains("mobile") { return "📱 Android".into() }
        return "📱 Tablet".into()
    }
    if u.contains("mac") { return "💻 Mac".into() }
    if u.contains("windows") { return "💻 Windows".into() }
    if u.contains("linux") { return "💻 Linux".into() }
    "❓ Other".into()
}

// is_bot — возвращает true если User-Agent принадлежит боту/краулеру
// Фильтрует: поисковые боты, FB/TG превью, headless браузеры, мониторинг
fn is_bot(ua: &str) -> bool {
    if ua.is_empty() { return true; }
    let u = ua.to_lowercase();
    let bot_keywords = [
        "bot", "crawler", "spider", "scraper", "slurp",
        "facebookexternalhit", "facebot", "linkedinbot", "twitterbot",
        "whatsapp", "telegrambot", "discordbot", "slackbot",
        "googlebot", "bingbot", "yandexbot", "baiduspider", "duckduckbot",
        "applebot", "semrushbot", "ahrefsbot", "mj12bot", "dotbot",
        "petalbot", "bytespider", "gptbot", "claudebot", "anthropic",
        "headlesschrome", "phantomjs", "selenium", "puppeteer", "playwright",
        "python-requests", "python-urllib", "go-http-client", "java/",
        "curl/", "wget/", "libwww", "okhttp", "axios/", "node-fetch",
        "preview", "prerender", "lighthouse", "pagespeed", "gtmetrix",
    ];
    bot_keywords.iter().any(|kw| u.contains(kw))
}


// source_from_ref — определяет источник трафика по Referer заголовку
// Используется как запасной вариант если нет utm параметров
fn source_from_ref(rf: &str) -> String {
    if rf.is_empty() { return "Direct".into() }
    let r = rf.to_lowercase();
    if r.contains("tiktok") { return "TikTok".into() }
    if r.contains("youtu") { return "YouTube".into() }
    if r.contains("google") { return "Google".into() }
    if r.contains("instagram") { return "Instagram".into() }
    if r.contains("facebook") || r.contains("fb.") { return "Facebook".into() }
    if r.contains("twitter") || r.contains("t.co") { return "Twitter".into() }
    "Other".into()
}

// ── Facebook CAPI (Conversions API — серверная отправка событий в ФБ) ─────────

// capi_post — базовая функция отправки события в Facebook Graph API
// Если есть тестовый код (FB_TEST_CODE) — добавляет его для Test Events
// Возвращает true только если FB ответил 2xx
async fn capi_post(pixel_id: String, token: String, mut body: serde_json::Value, test_code: String) -> bool {
    if !test_code.is_empty() {
        body["test_event_code"] = serde_json::Value::String(test_code);
    }
    let url = format!(
        "https://graph.facebook.com/v21.0/{}/events",
        pixel_id
    );
    let body_str = match serde_json::to_string(&body) {
        Ok(s) => s,
        Err(_) => return false,
    };
    let headers = Headers::new();
    let _ = headers.set("Content-Type", "application/json");
    let _ = headers.set("Authorization", &format!("Bearer {}", token));
    let mut init = RequestInit::new();
    init.with_method(Method::Post)
        .with_headers(headers)
        .with_body(Some(JsValue::from_str(&body_str)));
    if let Ok(req) = Request::new_with_init(&url, &init) {
        match Fetch::Request(req).send().await {
            Err(e) => { console_error!("CAPI post error: {:?}", e); false }
            Ok(mut resp) => {
                let status = resp.status_code();
                let text = resp.text().await.unwrap_or_default();
                console_log!("CAPI response {} : {}", status, text);
                status >= 200 && status < 300
            }
        }
    } else {
        false
    }
}

// send_capi_pageview — отправляет событие PageView в ФБ через CAPI
// Срабатывает когда посетитель пришёл с ФБ рекламы (есть fbclid в URL)
// Вместе с пикселем в браузере обеспечивает двойное отслеживание
async fn send_capi_pageview(pixel_id: String, token: String, test_code: String, fbclid: String, ua: String, t: i64) -> bool {
    let fbc = format!("fb.1.{}.{}", t / 1000, fbclid);
    let mut ud = serde_json::json!({ "fbc": fbc });
    if !ua.is_empty() {
        ud["client_user_agent"] = serde_json::Value::String(ua);
    }
    let body = serde_json::json!({
        "data": [{
            "event_name": "PageView",
            "event_time": t / 1000,
            "event_id": rand_hex(8),
            "action_source": "website",
            "user_data": ud
        }]
    });
    capi_post(pixel_id, token, body, test_code).await
}

// send_capi — отправляет событие Purchase (Покупка) в ФБ через CAPI
// Срабатывает когда в дашборде нажимают кнопку "💰 Sale"
// event_id используется для дедупликации (ФБ не считает дважды)
async fn send_capi(pixel_id: &str, token: &str, test_code: &str, p: &Purchase) -> bool {
    let mut ud = serde_json::json!({});
    if !p.fbclid.is_empty() {
        let fbc = format!("fb.1.{}.{}", p.visit_t / 1000, p.fbclid);
        ud["fbc"] = serde_json::Value::String(fbc);
    }
    if !p.ua.is_empty() {
        ud["client_user_agent"] = serde_json::Value::String(p.ua.clone());
    }
    let body = serde_json::json!({
        "data": [{
            "event_name": "Purchase",
            "event_time": p.t / 1000,
            "event_id": p.event_id,
            "action_source": "website",
            "user_data": ud,
            "custom_data": {
                "value": p.amount,
                "currency": p.currency
            }
        }]
    });
    capi_post(pixel_id.to_string(), token.to_string(), body, test_code.to_string()).await
}

// send_capi_lead — отправляет событие Lead в ФБ через CAPI
// Срабатывает когда в дашборде нажимают кнопку "👤 Lead"
async fn send_capi_lead(pixel_id: &str, token: &str, test_code: &str, fbclid: &str, ua: &str, visit_t: i64, event_id: &str) -> bool {
    let mut ud = serde_json::json!({});
    if !fbclid.is_empty() {
        let fbc = format!("fb.1.{}.{}", visit_t / 1000, fbclid);
        ud["fbc"] = serde_json::Value::String(fbc);
    }
    if !ua.is_empty() {
        ud["client_user_agent"] = serde_json::Value::String(ua.to_string());
    }
    let now = Date::now().as_millis() as i64;
    let body = serde_json::json!({
        "data": [{
            "event_name": "Lead",
            "event_time": now / 1000,
            "event_id": event_id,
            "action_source": "website",
            "user_data": ud
        }]
    });
    capi_post(pixel_id.to_string(), token.to_string(), body, test_code.to_string()).await
}

// ── D1 helpers (Вспомогательные функции для базы данных D1) ──────────────────

// d1_str / d1_i64 / d1_f64 / d1_bool — читают поле из строки D1 по имени колонки
fn d1_str(row: &serde_json::Value, key: &str) -> String {
    row.get(key).and_then(|v| v.as_str()).unwrap_or("").to_string()
}

fn d1_i64(row: &serde_json::Value, key: &str) -> i64 {
    row.get(key).and_then(|v| v.as_i64()).unwrap_or(0)
}

fn d1_f64(row: &serde_json::Value, key: &str) -> f64 {
    row.get(key).and_then(|v| v.as_f64()).unwrap_or(0.0)
}

fn d1_bool(row: &serde_json::Value, key: &str) -> bool {
    row.get(key).and_then(|v| v.as_i64()).unwrap_or(0) != 0
}

// row_to_visit / row_to_purchase / row_to_tg — конвертируют строку D1 в структуру Rust
fn row_to_visit(row: &serde_json::Value) -> Visit {
    Visit {
        id:     d1_i64(row, "id"),
        t:      d1_i64(row, "t"),
        h:      d1_str(row, "h"),
        co:     d1_str(row, "co"),
        ci:     d1_str(row, "ci"),
        d:      d1_str(row, "d"),
        s:      d1_str(row, "s"),
        rf:     d1_str(row, "rf"),
        fbclid: d1_str(row, "fbclid"),
        utm_c:  d1_str(row, "utm_c"),
        utm_ct: d1_str(row, "utm_ct"),
        utm_as: d1_str(row, "utm_as"),
        ua:     d1_str(row, "ua"),
        vid:    d1_str(row, "vid"),
    }
}

fn row_to_purchase(row: &serde_json::Value) -> Purchase {
    Purchase {
        id:       d1_i64(row, "id"),
        t:        d1_i64(row, "t"),
        fbclid:   d1_str(row, "fbclid"),
        amount:   d1_f64(row, "amount"),
        currency: d1_str(row, "currency"),
        visit_t:  d1_i64(row, "visit_t"),
        ua:       d1_str(row, "ua"),
        event_id: d1_str(row, "event_id"),
        capi_ok:  d1_bool(row, "capi_ok"),
        utm_c:    d1_str(row, "utm_c"),
    }
}

fn row_to_registration(row: &serde_json::Value) -> Registration {
    Registration {
        t:        d1_i64(row, "t"),
        fbclid:   d1_str(row, "fbclid"),
        visit_t:  d1_i64(row, "visit_t"),
        ua:       d1_str(row, "ua"),
        event_id: d1_str(row, "event_id"),
        capi_ok:  d1_bool(row, "capi_ok"),
        utm_c:    d1_str(row, "utm_c"),
    }
}

fn row_to_tg(row: &serde_json::Value) -> TgLink {
    TgLink {
        id:       d1_i64(row, "id"),
        t:        d1_i64(row, "t"),
        vid:      d1_str(row, "vid"),
        tg_id:    d1_i64(row, "tg_id"),
        tg_user:  d1_str(row, "tg_user"),
        tg_name:  d1_str(row, "tg_name"),
    }
}

// d1_rows — выполняет SELECT запрос, возвращает список строк
async fn d1_rows(db: &D1Database, sql: &str, params: Vec<wasm_bindgen::JsValue>) -> Vec<serde_json::Value> {
    let stmt = match db.prepare(sql).bind(&params) {
        Ok(s) => s,
        Err(e) => { console_error!("D1 bind: {:?}", e); return vec![]; }
    };
    let result = match stmt.all().await {
        Ok(r) => r,
        Err(e) => { console_error!("D1 all: {:?}", e); return vec![]; }
    };
    match result.results::<serde_json::Value>() {
        Ok(v) => v,
        Err(e) => { console_error!("D1 results: {:?}", e); vec![] }
    }
}

// d1_exec — выполняет INSERT/UPDATE запрос, возвращает ID новой записи
async fn d1_exec(db: &D1Database, sql: &str, params: Vec<wasm_bindgen::JsValue>) -> Option<i64> {
    let stmt = match db.prepare(sql).bind(&params) {
        Ok(s) => s,
        Err(e) => { console_error!("D1 exec bind: {:?}", e); return None; }
    };
    match stmt.run().await {
        Ok(meta) => {
            if let Some(m) = meta.meta().ok().flatten() {
                m.last_row_id
            } else {
                None
            }
        }
        Err(e) => { console_error!("D1 exec run: {:?}", e); None }
    }
}

// ── Dashboard HTML (HTML страницы дашборда и логина) ─────────────────────────

// LOGIN_PAGE — страница входа /analytics (форма с логином и паролем)
const LOGIN_PAGE: &str = r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dashboard Login</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#0a0f1a;color:#e2e8f0;display:flex;align-items:center;justify-content:center;min-height:100vh}.box{background:#1a2332;border-radius:16px;padding:36px 32px;width:340px;max-width:90vw}h1{font-size:20px;margin-bottom:24px;text-align:center}label{font-size:12px;color:#94a3b8;display:block;margin-bottom:6px}input{width:100%;background:#0a0f1a;border:1px solid #2a3444;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:16px;outline:none}button{width:100%;background:#3b82f6;color:#fff;border:none;padding:12px;border-radius:8px;font-size:15px;cursor:pointer;margin-top:4px}.err{color:#ef4444;font-size:13px;text-align:center;margin-top:12px;display:none}</style></head><body><div class="box"><h1>Analytics Dashboard</h1><form id="f"><label>Login</label><input type="text" id="l" autocomplete="username"><label>Password</label><input type="password" id="p" autocomplete="current-password"><button type="submit">Sign In</button></form><div class="err" id="e">Wrong login or password</div></div><script>document.getElementById('f').onsubmit=async function(ev){ev.preventDefault();var l=document.getElementById('l').value;var p=document.getElementById('p').value;var r=await fetch('/analytics/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({l:l,p:p})});if(r.ok){location.href='/analytics'}else{document.getElementById('e').style.display='block'}};</script></body></html>"#;

// DASH — главная страница дашборда (вкладки: Activity, Countries, Devices, Sources, Purchases, Telegram)
// Обновляется каждые 5 секунд через /api/stats, кнопка Sale отправляет на /api/purchase
const DASH: &str = r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Dashboard</title><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;background:#0a0f1a;color:#e2e8f0;padding:20px}.wrap{max-width:1400px;margin:0 auto}.hdr{display:flex;align-items:center;gap:12px;margin-bottom:20px}h1{font-size:22px}.live{display:flex;align-items:center;gap:6px;font-size:12px;color:#64748b}.dot{width:8px;height:8px;border-radius:50%;background:#10b981;animation:pulse 2s infinite}.dot.err{background:#ef4444;animation:none}@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}.stat{background:#1a2332;border-radius:12px;padding:20px;text-align:center}.stat-v{font-size:32px;font-weight:700;color:#3b82f6}.stat-l{font-size:12px;color:#64748b;margin-top:4px}.stat.grn .stat-v{color:#10b981}.stat.prp .stat-v{color:#a855f7}.stat.yel .stat-v{color:#f59e0b}.tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}.tab{background:#1a2332;border:none;color:#94a3b8;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:13px}.tab.on{background:#3b82f6;color:#fff}.panel{display:none}.panel.on{display:block}.card{background:#1a2332;border-radius:12px;padding:20px;margin-bottom:16px}.card-t{font-size:14px;font-weight:600;margin-bottom:16px}.bar{margin-bottom:12px}.bar-h{display:flex;justify-content:space-between;font-size:13px;margin-bottom:4px}.bar-t{height:8px;background:#0a0f1a;border-radius:4px}.bar-f{height:100%;border-radius:4px;transition:width .5s}.tbl{background:#1a2332;border-radius:12px;overflow:hidden}.tbl-h{padding:16px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #2a3444}.tbl-s{overflow:auto}table{width:100%;border-collapse:collapse}th,td{padding:12px;text-align:left;font-size:13px}th{background:#0f1520;color:#64748b;font-size:11px;text-transform:uppercase;position:sticky;top:0}tr:hover{background:#0f1520}tr.new{animation:flash .8s ease-out}.btn{background:#3b82f6;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px}.btn.grn{background:#10b981}.btn.sm{padding:4px 10px;font-size:11px}.btn.cancel{background:#2a3444}.btn.ghost{background:#1a2332;color:#94a3b8;border:1px solid #2a3444}.btn:disabled{opacity:.4;cursor:default}.empty{color:#64748b;text-align:center;padding:40px}.pag{display:flex;align-items:center;gap:8px;padding:12px 16px;border-top:1px solid #2a3444}.pag-info{font-size:12px;color:#64748b;flex:1}@keyframes flash{0%{background:#1e3a5f}100%{background:transparent}}.overlay{display:none;position:fixed;inset:0;background:rgba(0,0,0,.75);z-index:100;align-items:center;justify-content:center}.overlay.show{display:flex}.modal{background:#1a2332;border-radius:16px;padding:28px;width:380px;max-width:90vw}.modal h2{font-size:16px;margin-bottom:20px}.modal label{font-size:12px;color:#94a3b8;display:block;margin-bottom:6px}.modal input,.modal select{width:100%;background:#0a0f1a;border:1px solid #2a3444;color:#e2e8f0;padding:10px 12px;border-radius:8px;font-size:14px;margin-bottom:14px;outline:none}.modal-btns{display:flex;gap:12px;margin-top:8px}.modal-btns .btn{flex:1;padding:10px}.fbc-hint{font-size:11px;color:#64748b;margin-bottom:14px;word-break:break-all}@media(max-width:768px){.stats{grid-template-columns:repeat(2,1fr)}}@media(max-width:480px){.stats{grid-template-columns:1fr}}</style></head><body><div class="wrap"><div class="hdr"><h1>Analytics Dashboard</h1><div class="live"><div class="dot" id="dot"></div><span id="upd">connecting...</span></div></div><div class="stats"><div class="stat"><div class="stat-v" id="tot">-</div><div class="stat-l">TOTAL VISITS</div></div><div class="stat grn"><div class="stat-v" id="s_pur">-</div><div class="stat-l">PURCHASES</div></div><div class="stat prp"><div class="stat-v" id="s_rev">-</div><div class="stat-l">REVENUE</div></div><div class="stat yel"><div class="stat-v" id="s_cr">-</div><div class="stat-l">CONV RATE</div></div></div><div class="tabs"><button class="tab on" data-p="0">Activity</button><button class="tab" data-p="1">Countries</button><button class="tab" data-p="2">Devices</button><button class="tab" data-p="3">Sources</button><button class="tab" data-p="4">💰 Purchases</button><button class="tab" data-p="5">👤 Leads</button><button class="tab" data-p="6">💬 Telegram</button></div><div id="p0" class="panel on"><div class="tbl"><div class="tbl-h"><span>Recent Activity</span><div style="display:flex;gap:8px"><button class="btn" onclick="fetchData()">Refresh</button><button class="btn" style="background:#ef4444" onclick="delAll(\'visits\')">🗑 Delete All</button></div></div><div style="padding:12px 16px;display:flex;gap:8px;flex-wrap:wrap;border-bottom:1px solid #2a3444"><input id="srch" type="text" placeholder="Search TG user, name, ID, source, country..." style="flex:1;min-width:200px;background:#0a0f1a;border:1px solid #2a3444;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:13px;outline:none" oninput="vPage=0;renderVisitPage()"><select id="f_src" style="background:#0a0f1a;border:1px solid #2a3444;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:13px;outline:none" onchange="vPage=0;renderVisitPage()"><option value="">All Sources</option></select><select id="f_co" style="background:#0a0f1a;border:1px solid #2a3444;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:13px;outline:none" onchange="vPage=0;renderVisitPage()"><option value="">All Countries</option></select><button class="btn ghost" onclick="document.getElementById(\'srch\').value=\'\';document.getElementById(\'f_src\').value=\'\';document.getElementById(\'f_co\').value=\'\';vPage=0;renderVisitPage()">✕ Reset</button></div><div class="tbl-s"><table><thead><tr><th>Time</th><th>Location</th><th>Device</th><th>Source</th><th>Campaign</th><th>fbclid</th><th>Telegram</th><th></th></tr></thead><tbody id="rows"></tbody></table></div><div class="pag"><span class="pag-info" id="pag_info"></span><button class="btn ghost" id="pag_prev" onclick="pg(vPage-1)">← Prev</button><button class="btn ghost" id="pag_next" onclick="pg(vPage+1)">Next →</button></div></div></div><div id="p1" class="panel"><div class="card"><div class="card-t">Top Countries</div><div id="c_co"></div></div></div><div id="p2" class="panel"><div class="card"><div class="card-t">Devices</div><div id="c_dv"></div></div></div><div id="p3" class="panel"><div class="card"><div class="card-t">Traffic Sources</div><div id="c_sr"></div></div></div><div id="p4" class="panel"><div class="tbl"><div class="tbl-h"><span>Purchase History</span><button class="btn" style="background:#ef4444" onclick="delAll(\'purchases\')">🗑 Delete All</button></div><div class="tbl-s"><table><thead><tr><th>Time</th><th>Amount</th><th>Currency</th><th>CAPI</th><th>Campaign</th><th>fbclid</th><th></th></tr></thead><tbody id="prows"></tbody></table></div><div class="pag"><span class="pag-info" id="ppag_info"></span><button class="btn ghost" id="ppag_prev" onclick="ppg(pPage-1)">← Prev</button><button class="btn ghost" id="ppag_next" onclick="ppg(pPage+1)">Next →</button></div></div></div><div id="p5" class="panel"><div class="tbl"><div class="tbl-h"><span>Leads</span><button class="btn" style="background:#ef4444" onclick="delAll(\'registrations\')">🗑 Delete All</button></div><div class="tbl-s"><table><thead><tr><th>Time</th><th>CAPI</th><th>Campaign</th><th>fbclid</th></tr></thead><tbody id="regrows"></tbody></table></div><div class="pag"><span class="pag-info" id="rpag_info"></span><button class="btn ghost" id="rpag_prev" onclick="rpg(rPage-1)">← Prev</button><button class="btn ghost" id="rpag_next" onclick="rpg(rPage+1)">Next →</button></div></div></div><div id="p6" class="panel"><div class="tbl"><div class="tbl-h"><span>Telegram Users</span><button class="btn" style="background:#ef4444" onclick="delAll(\'tg_links\')">🗑 Delete All</button></div><div style="padding:12px 16px;border-bottom:1px solid #2a3444"><input id="tg_srch" type="text" placeholder="Search username, name, Telegram ID..." style="width:100%;background:#0a0f1a;border:1px solid #2a3444;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:13px;outline:none" oninput="renderTgTable()"></div><div class="tbl-s"><table><thead><tr><th>Time</th><th>Username / Name</th><th>Telegram ID</th><th>Visit ID</th><th></th></tr></thead><tbody id="tgrows"></tbody></table></div></div></div></div><div class="overlay" id="overlay"><div class="modal"><h2>💰 Register Sale</h2><label>Amount</label><input type="number" id="m_amount" placeholder="0.00" step="0.01" min="0"><label>Currency</label><select id="m_cur"><option value="USD">USD</option><option value="EUR">EUR</option><option value="GBP">GBP</option><option value="RUB">RUB</option><option value="UAH">UAH</option></select><div class="fbc-hint" id="m_fbc"></div><div class="modal-btns"><button class="btn cancel" onclick="closeModal()">Cancel</button><button class="btn grn" id="m_btn" onclick="submitSale()">Confirm Sale</button></div></div></div><script>var K='__APIKEY__';var F={US:'🇺🇸',GB:'🇬🇧',DE:'🇩🇪',FR:'🇫🇷',NL:'🇳🇱',RU:'🇷🇺',UA:'🇺🇦',PL:'🇵🇱',IT:'🇮🇹',ES:'🇪🇸',BR:'🇧🇷',CA:'🇨🇦',AU:'🇦🇺',JP:'🇯🇵',KR:'🇰🇷',CN:'🇨🇳',IN:'🇮🇳',TR:'🇹🇷',VN:'🇻🇳',TH:'🇹🇭',CO:'🇨🇴',MX:'🇲🇽',AR:'🇦🇷',PH:'🇵🇭',ID:'🇮🇩',MY:'🇲🇾',SG:'🇸🇬',SA:'🇸🇦',AE:'🇦🇪',EG:'🇪🇬',ZA:'🇿🇦',PT:'🇵🇹',GR:'🇬🇷',CZ:'🇨🇿',RO:'🇷🇴',HU:'🇭🇺',SK:'🇸🇰',BG:'🇧🇬',HR:'🇭🇷',RS:'🇷🇸',FI:'🇫🇮',SE:'🇸🇪',NO:'🇳🇴',DK:'🇩🇰',CH:'🇨🇭',AT:'🇦🇹',BE:'🇧🇪',IE:'🇮🇪',IL:'🇮🇱',IR:'🇮🇷',PK:'🇵🇰',BD:'🇧🇩',NG:'🇳🇬',KE:'🇰🇪',MA:'🇲🇦',DZ:'🇩🇿',TN:'🇹🇳',IQ:'🇮🇶',SY:'🇸🇾',LB:'🇱🇧',JO:'🇯🇴',KW:'🇰🇼',QA:'🇶🇦',BH:'🇧🇭',OM:'🇴🇲',YE:'🇾🇪',KZ:'🇰🇿',UZ:'🇺🇿',AZ:'🇦🇿',GE:'🇬🇪',AM:'🇦🇲',BY:'🇧🇾',MD:'🇲🇩',LT:'🇱🇹',LV:'🇱🇻',EE:'🇪🇪',CL:'🇨🇱',PE:'🇵🇪',VE:'🇻🇪',EC:'🇪🇨',BO:'🇧🇴',PY:'🇵🇾',UY:'🇺🇾',GT:'🇬🇹',HN:'🇭🇳',SV:'🇸🇻',NI:'🇳🇮',CR:'🇨🇷',PA:'🇵🇦',DO:'🇩🇴',CU:'🇨🇺',HT:'🇭🇹',NZ:'🇳🇿',TW:'🇹🇼',HK:'🇭🇰',MO:'🇲🇴',MM:'🇲🇲',KH:'🇰🇭',LA:'🇱🇦',NP:'🇳🇵',LK:'🇱🇰',MN:'🇲🇳',AF:'🇦🇫',TJ:'🇹🇯',TM:'🇹🇲',KG:'🇰🇬'};var PAGE=10;var prevTotal=0;var visitMap={};var saleData={};var allVisits=[];var allPurchases=[];var vPage=0;var pPage=0;var rPage=0;var allRegs=[];var allTgLinks=[];document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){document.querySelectorAll('.tab').forEach(function(x){x.classList.remove('on')});document.querySelectorAll('.panel').forEach(function(x){x.classList.remove('on')});t.classList.add('on');document.getElementById('p'+t.dataset.p).classList.add('on')}});function bar(data,color){var arr=Object.entries(data||{}).sort(function(a,b){return b[1]-a[1]}).slice(0,10);if(!arr.length)return'<div class="empty">No data</div>';var max=arr[0][1];return arr.map(function(x){return'<div class="bar"><div class="bar-h"><span>'+x[0]+'</span><span>'+x[1]+'</span></div><div class="bar-t"><div class="bar-f" style="width:'+Math.round(x[1]/max*100)+'%;background:'+color+'"></div></div></div>'}).join('')}function time(t){try{var d=new Date(typeof t==='number'?t:parseInt(t));return d.toLocaleString('en-GB',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZone:'America/Los_Angeles'})+' PT'}catch(e){return'-'}}function openSale(vid){var v=visitMap[vid];if(!v)return;saleData={fbclid:v.fbclid,visit_t:v.t,ua:v.ua,utm_c:v.utm_c||''};document.getElementById('m_fbc').textContent=v.fbclid?'fbclid: '+(v.fbclid.length>50?v.fbclid.slice(0,50)+'...':v.fbclid):'⚠️ No fbclid (organic — CAPI will not fire)';document.getElementById('m_amount').value='';document.getElementById('overlay').classList.add('show')}function closeModal(){document.getElementById('overlay').classList.remove('show')}async function submitSale(){var amount=parseFloat(document.getElementById('m_amount').value);var currency=document.getElementById('m_cur').value;if(!amount||amount<=0){alert('Enter valid amount');return}var btn=document.getElementById('m_btn');btn.textContent='Sending...';btn.disabled=true;try{var r=await fetch('/api/purchase',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:K,fbclid:saleData.fbclid,amount:amount,currency:currency,visit_t:saleData.visit_t,ua:saleData.ua,utm_c:saleData.utm_c})});var d=await r.json();closeModal();if(d.capi_ok){alert('✅ Sale registered! CAPI sent (ID: '+d.event_id+')')}else{alert('✅ Sale saved. CAPI failed — check FB_PIXEL_ID / FB_ACCESS_TOKEN.')}fetchData()}catch(e){alert('Error: '+e.message)}finally{btn.textContent='Confirm Sale';btn.disabled=false}}async function sendLead(vid){var v=visitMap[vid];if(!v)return;try{var r=await fetch('/api/registration',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:K,fbclid:v.fbclid,visit_t:v.t,ua:v.ua,utm_c:v.utm_c||''})});var d=await r.json();if(d.capi_ok){alert('✅ Lead sent! (ID: '+d.event_id+')')}else{alert('❌ CAPI failed — check FB_PIXEL_ID / FB_ACCESS_TOKEN.')}}catch(e){alert('Error: '+e.message)}}function filteredVisits(){var q=(document.getElementById('srch')||{value:''}).value.toLowerCase();var fs=(document.getElementById('f_src')||{value:''}).value;var fc=(document.getElementById('f_co')||{value:''}).value;return allVisits.filter(function(v){var tg=window._tgMap&&window._tgMap[v.vid];var tgStr=tg?((tg.tg_user||'')+(tg.tg_name||'')+(tg.tg_id||'')).toLowerCase():'';if(q&&!(v.co+v.ci+v.s+v.utm_c+v.fbclid+tgStr).toLowerCase().includes(q))return false;if(fs&&(v.s||'Direct')!==fs)return false;if(fc&&v.co!==fc)return false;return true})}function pg(n){var total=filteredVisits().length;var maxP=Math.max(0,Math.ceil(total/PAGE)-1);vPage=Math.max(0,Math.min(n,maxP));renderVisitPage()}function ppg(n){var total=allPurchases.length;var maxP=Math.max(0,Math.ceil(total/PAGE)-1);pPage=Math.max(0,Math.min(n,maxP));renderPurchasePage()}function rpg(n){var total=allRegs.length;var maxP=Math.max(0,Math.ceil(total/PAGE)-1);rPage=Math.max(0,Math.min(n,maxP));renderRegPage()}function renderRegPage(){var total=allRegs.length;var start=rPage*PAGE;var slice=allRegs.slice(start,start+PAGE);document.getElementById('rpag_info').textContent='Showing '+(total?start+1:0)+'-'+Math.min(start+PAGE,total)+' of '+total;document.getElementById('rpag_prev').disabled=rPage===0;document.getElementById('rpag_next').disabled=start+PAGE>=total;var html=slice.map(function(r){var capiStatus=r.capi_ok?'<span style="color:#10b981">✅ Sent</span>':'<span style="color:#ef4444">❌ Failed</span>';var fbc=r.fbclid?r.fbclid.slice(0,16)+'...':'—';return'<tr><td>'+time(r.t)+'</td><td>'+capiStatus+'</td><td>'+(r.utm_c||'—')+'</td><td>'+fbc+'</td></tr>'}).join('');document.getElementById('regrows').innerHTML=html||'<tr><td colspan="4" class="empty">No leads yet</td></tr>'}function renderVisitPage(){var fv=filteredVisits();var total=fv.length;var start=vPage*PAGE;var slice=fv.slice(start,start+PAGE);document.getElementById('pag_info').textContent='Showing '+(total?start+1:0)+'-'+Math.min(start+PAGE,total)+' of '+total+(total!==allVisits.length?' (filtered from '+allVisits.length+')':'');document.getElementById('pag_prev').disabled=vPage===0;document.getElementById('pag_next').disabled=start+PAGE>=total;var html=slice.map(function(v,i){var flag=F[v.co]||'🌍';var city=v.ci&&v.ci!=='??'?' • '+v.ci:'';var isNew=i===0&&vPage===0&&allVisits.length>prevTotal?'new':'';var fbc=v.fbclid?'<span style="color:#10b981">✅</span>':'—';var camp=v.utm_c?'<span style="color:#f59e0b;font-size:11px">'+v.utm_c+(v.utm_as?'<br><span style="color:#94a3b8">'+v.utm_as+'</span>':'')+'</span>':'—';var tg=v.vid&&window._tgMap&&window._tgMap[v.vid];var tgCell=tg?(tg.tg_user?'<a href="https://t.me/'+tg.tg_user+'" target="_blank" style="color:#3b82f6">@'+tg.tg_user+'</a>':'<span style="color:#f59e0b">'+(tg.tg_name||'—')+'</span> <span style="color:#64748b;font-size:11px">ID:'+tg.tg_id+'</span>'):'—';var isFb=v.vid;var btns=isFb?'<button class="btn grn sm" onclick="openSale(\''+v.vid+'\')">💰 Sale</button> <button class="btn sm" style="background:#8b5cf6" onclick="sendLead(\''+v.vid+'\')">👤 Lead</button> ':'';btns+='<button class="btn sm" style="background:#ef4444" onclick="delRow(\'visits\','+v.id+')">✕</button>';return'<tr class="'+isNew+'"><td>'+time(v.t)+'</td><td>'+flag+' '+v.co+city+'</td><td>'+v.d+'</td><td>'+(v.s||'Direct')+'</td><td>'+camp+'</td><td>'+fbc+'</td><td>'+tgCell+'</td><td style="white-space:nowrap">'+btns+'</td></tr>'}).join('');document.getElementById('rows').innerHTML=html||'<tr><td colspan="8" class="empty">No visits yet</td></tr>'}function renderPurchasePage(){var total=allPurchases.length;var start=pPage*PAGE;var slice=allPurchases.slice(start,start+PAGE);document.getElementById('ppag_info').textContent='Showing '+(total?start+1:0)+'-'+Math.min(start+PAGE,total)+' of '+total;document.getElementById('ppag_prev').disabled=pPage===0;document.getElementById('ppag_next').disabled=start+PAGE>=total;var phtml=slice.map(function(p){var capiStatus=p.capi_ok?'<span style="color:#10b981">✅ Sent</span>':'<span style="color:#ef4444">❌ Failed</span>';var fbc=p.fbclid?p.fbclid.slice(0,16)+'...':'—';return'<tr><td>'+time(p.t)+'</td><td><b>'+p.amount.toFixed(2)+'</b></td><td>'+p.currency+'</td><td>'+capiStatus+'</td><td>'+(p.utm_c||'—')+'</td><td>'+fbc+'</td><td><button class="btn sm" style="background:#ef4444" onclick="delRow(\'purchases\','+p.id+')">✕</button></td></tr>'}).join('');document.getElementById('prows').innerHTML=phtml||'<tr><td colspan="7" class="empty">No purchases yet</td></tr>'}function render(D){var s=D.stats;var newTotal=s.total;document.getElementById('tot').textContent=newTotal;document.getElementById('s_pur').textContent=s.purchases||0;document.getElementById('s_rev').textContent=(s.revenue||0).toFixed(2);var cr=newTotal>0?((s.purchases||0)/newTotal*100).toFixed(1)+'%':'0.0%';document.getElementById('s_cr').textContent=cr;var co={};Object.entries(s.countries||{}).forEach(function(x){co[(F[x[0]]||'🌍')+' '+x[0]]=x[1]});document.getElementById('c_co').innerHTML=bar(co,'#3b82f6');document.getElementById('c_dv').innerHTML=bar(s.devices,'#10b981');document.getElementById('c_sr').innerHTML=bar(s.sources,'#a855f7');visitMap={};(D.visits||[]).forEach(function(v){if(v.vid)visitMap[v.vid]=v});window._tgMap={};(D.tg_links||[]).forEach(function(l){if(l.vid)window._tgMap[l.vid]=l});allVisits=D.visits||[];allPurchases=D.purchases||[];allRegs=D.registrations||[];if(newTotal>prevTotal)vPage=0;updateFilters();renderVisitPage();renderPurchasePage();renderRegPage();allTgLinks=D.tg_links||[];renderTgTable();prevTotal=newTotal}async function fetchData(){var dot=document.getElementById('dot');var upd=document.getElementById('upd');try{var r=await fetch('/api/stats?key='+K);if(!r.ok)throw new Error(r.status);var d=await r.json();render(d);dot.classList.remove('err');upd.textContent='updated '+new Date().toLocaleTimeString('en-GB',{hour:'2-digit',minute:'2-digit',second:'2-digit'})}catch(e){dot.classList.add('err');upd.textContent='error - retrying...';console.error(e)}}function renderTgTable(){var q=(document.getElementById('tg_srch')||{value:''}).value.toLowerCase();var list=allTgLinks.filter(function(l){if(!q)return true;return(l.tg_user||'').toLowerCase().includes(q)||(l.tg_name||'').toLowerCase().includes(q)||(l.tg_id||'').toString().includes(q)});var html=list.slice(0,500).map(function(l){var user=l.tg_user?'<a href="https://t.me/'+l.tg_user+'" target="_blank" style="color:#3b82f6">@'+l.tg_user+'</a>':'<span style="color:#f59e0b">'+(l.tg_name||'—')+'</span>';return'<tr><td>'+time(l.t)+'</td><td>'+user+(l.tg_name&&l.tg_user?' <span style="color:#64748b;font-size:11px">'+l.tg_name+'</span>':'')+'</td><td style="color:#94a3b8">'+l.tg_id+'</td><td style="color:#64748b">'+l.vid+'</td><td><button class="btn sm" style="background:#ef4444" onclick="delRow(\'tg_links\','+l.id+')">✕</button></td></tr>'}).join('');document.getElementById('tgrows').innerHTML=html||'<tr><td colspan="5" class="empty">No Telegram users yet</td></tr>'}async function delRow(table,id){try{await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:K,table:table,id:id})});fetchData()}catch(e){}}async function delAll(table){try{await fetch('/api/delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({key:K,table:table,all:true})});fetchData()}catch(e){}}function updateFilters(){var srcs=new Set();var cos=new Set();allVisits.forEach(function(v){srcs.add(v.s||'Direct');cos.add(v.co)});var se=document.getElementById('f_src');if(se){var cv=se.value;se.innerHTML='<option value="">All Sources</option>';Array.from(srcs).sort().forEach(function(s){se.innerHTML+='<option value="'+s+'"'+(cv===s?' selected':'')+'>'+s+'</option>'})}var ce=document.getElementById('f_co');if(ce){var ccv=ce.value;ce.innerHTML='<option value="">All Countries</option>';Array.from(cos).sort().forEach(function(c){ce.innerHTML+='<option value="'+c+'"'+(ccv===c?' selected':'')+'>'+c+'</option>'})}}fetchData();setInterval(function(){if(!document.hidden){fetchData()}},5000);document.addEventListener('visibilitychange',function(){if(!document.hidden){fetchData()}})</script></body></html>"#;

// ── Auth cookie helpers (Вспомогательные функции авторизации) ─────────────────

// check_auth — проверяет есть ли cookie auth=1 в запросе (значит уже залогинен)
fn check_auth(req: &Request) -> bool {
    let cookie = hdr(req.headers(), "cookie");
    cookie.split(';').any(|part| {
        let p = part.trim();
        p == "auth=1" || p.starts_with("auth=1 ") || p.starts_with("auth=1;")
    })
}

// set_auth_cookie — создаёт строку cookie auth=1 (живёт 24 часа, только для /analytics)
fn set_auth_cookie() -> String {
    "auth=1; Path=/analytics; HttpOnly; SameSite=Strict; Max-Age=86400".to_string()
}

// ── Main entry (Главная точка входа — обрабатывает все HTTP запросы) ──────────

#[event(fetch)]
async fn fetch(mut req: Request, env: Env, ctx: Context) -> Result<Response> {
    let url = req.url()?;
    let path = url.path();
    let db = env.d1("analytics_db")?;
    let analytics_key = env.secret("ANALYTICS_KEY").map(|v| v.to_string()).unwrap_or_default();

    match path {
        // /analytics — дашборд (показывает если залогинен, иначе форму логина)
        "/analytics" => {
            if !check_auth(&req) {
                return Response::from_html(LOGIN_PAGE);
            }
            let html = DASH.replace("__APIKEY__", &analytics_key);
            let mut resp = Response::from_html(&html)?;
            resp.headers_mut().set("Content-Type", "text/html; charset=utf-8")?;
            Ok(resp)
        }

        // /analytics/login — принимает {l, p}, проверяет логин/пароль, ставит cookie
        "/analytics/login" => {
            if req.method() != Method::Post {
                return Response::error("Method Not Allowed", 405);
            }
            #[derive(Deserialize)]
            struct LoginReq { l: String, p: String }
            let body: LoginReq = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            let dash_login = env.secret("DASH_LOGIN").map(|v| v.to_string()).unwrap_or_default();
            let dash_pass  = env.secret("DASH_PASS").map(|v| v.to_string()).unwrap_or_default();
            // Защита: если секреты не выставлены — запрещаем вход
            if dash_login.is_empty() || dash_pass.is_empty() {
                return Response::error("Unauthorized", 401);
            }
            if body.l == dash_login && body.p == dash_pass {
                let mut resp = Response::ok("")?;
                resp.headers_mut().set("Set-Cookie", &set_auth_cookie())?;
                Ok(resp)
            } else {
                Response::error("Unauthorized", 401)
            }
        }

        // /api/purchase — принимает продажу из дашборда (кнопка Sale)
        // Отправляет Purchase в ФБ CAPI и сохраняет в D1
        "/api/purchase" => {
            if req.method() != Method::Post {
                return Response::error("Method Not Allowed", 405);
            }
            let body: PurchaseReq = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            if body.key != analytics_key {
                return Response::error("Unauthorized", 401);
            }
            let now = Date::now().as_millis() as i64;
            let mut purchase = Purchase {
                id: 0,
                t: now,
                fbclid: body.fbclid,
                amount: body.amount,
                currency: if body.currency.is_empty() { "USD".into() } else { body.currency },
                visit_t: body.visit_t,
                ua: body.ua,
                event_id: rand_hex(8),
                capi_ok: false,
                utm_c: body.utm_c,
            };
            let pixel_id = env.var("FB_PIXEL_ID").map(|v| v.to_string()).unwrap_or_default();
            let token = env.secret("FB_ACCESS_TOKEN").map(|v| v.to_string()).unwrap_or_default();
            let test_code = env.var("FB_TEST_CODE").map(|v| v.to_string()).unwrap_or_default();
            if !pixel_id.is_empty() && !token.is_empty() {
                purchase.capi_ok = send_capi(&pixel_id, &token, &test_code, &purchase).await;
            }
            let capi_ok_int: i64 = if purchase.capi_ok { 1 } else { 0 };
            d1_exec(&db,
                "INSERT INTO purchases (t, fbclid, amount, currency, visit_t, ua, event_id, capi_ok, utm_c) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    JsValue::from_f64(purchase.t as f64),
                    JsValue::from_str(&purchase.fbclid),
                    JsValue::from_f64(purchase.amount),
                    JsValue::from_str(&purchase.currency),
                    JsValue::from_f64(purchase.visit_t as f64),
                    JsValue::from_str(&purchase.ua),
                    JsValue::from_str(&purchase.event_id),
                    JsValue::from_f64(capi_ok_int as f64),
                    JsValue::from_str(&purchase.utm_c),
                ],
            ).await;
            Response::from_json(&serde_json::json!({
                "ok": true,
                "capi_ok": purchase.capi_ok,
                "event_id": purchase.event_id
            }))
        }

        // /api/tg — принимает данные из бота когда пользователь написал /start
        // Связывает vid (ID визита с сайта) с telegram пользователем
        "/api/tg" => {
            if req.method() != Method::Post {
                return Response::error("Method Not Allowed", 405);
            }
            let body: TgReq = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            if body.key != analytics_key {
                return Response::error("Unauthorized", 401);
            }
            let now = Date::now().as_millis() as i64;
            d1_exec(&db,
                "INSERT INTO tg_links (t, vid, tg_id, tg_user, tg_name) VALUES (?, ?, ?, ?, ?) ON CONFLICT(tg_id) DO UPDATE SET t=excluded.t, vid=CASE WHEN excluded.vid IS NOT NULL AND excluded.vid != '' THEN excluded.vid ELSE tg_links.vid END, tg_user=excluded.tg_user, tg_name=excluded.tg_name",
                vec![
                    JsValue::from_f64(now as f64),
                    JsValue::from_str(&body.vid),
                    JsValue::from_f64(body.tg_id as f64),
                    JsValue::from_str(&body.tg_user),
                    JsValue::from_str(&body.tg_name),
                ],
            ).await;
            Response::from_json(&serde_json::json!({"ok": true}))
        }

        // /api/registration — принимает лид из дашборда (кнопка Lead)
        // Отправляет Lead в ФБ CAPI
        "/api/registration" => {
            if req.method() != Method::Post {
                return Response::error("Method Not Allowed", 405);
            }
            let body: RegReq = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            if body.key != analytics_key {
                return Response::error("Unauthorized", 401);
            }
            let now = Date::now().as_millis() as i64;
            let pixel_id = env.var("FB_PIXEL_ID").map(|v| v.to_string()).unwrap_or_default();
            let token = env.secret("FB_ACCESS_TOKEN").map(|v| v.to_string()).unwrap_or_default();
            let test_code = env.var("FB_TEST_CODE").map(|v| v.to_string()).unwrap_or_default();
            let event_id = rand_hex(8);
            let capi_ok = if !pixel_id.is_empty() && !token.is_empty() {
                send_capi_lead(&pixel_id, &token, &test_code, &body.fbclid, &body.ua, body.visit_t, &event_id).await
            } else {
                false
            };
            let capi_ok_int: i64 = if capi_ok { 1 } else { 0 };
            d1_exec(&db,
                "INSERT INTO registrations (t, fbclid, visit_t, ua, event_id, capi_ok, utm_c) VALUES (?, ?, ?, ?, ?, ?, ?)",
                vec![
                    JsValue::from_f64(now as f64),
                    JsValue::from_str(&body.fbclid),
                    JsValue::from_f64(body.visit_t as f64),
                    JsValue::from_str(&body.ua),
                    JsValue::from_str(&event_id),
                    JsValue::from_f64(capi_ok_int as f64),
                    JsValue::from_str(&body.utm_c),
                ],
            ).await;
            Response::from_json(&serde_json::json!({
                "ok": true,
                "capi_ok": capi_ok,
                "event_id": event_id
            }))
        }

        // /api/stats — отдаёт все данные для дашборда
        // Возвращает: статистику, визиты, покупки, telegram пользователей
        "/api/stats" => {
            let key = url.query_pairs()
                .find(|(k, _)| k == "key")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            if key != analytics_key {
                return Response::error("Unauthorized", 401);
            }

            let visit_rows  = d1_rows(&db, "SELECT * FROM visits        ORDER BY t DESC LIMIT 1000", vec![]).await;
            let pur_rows    = d1_rows(&db, "SELECT * FROM purchases     ORDER BY t DESC LIMIT 500",  vec![]).await;
            let reg_rows    = d1_rows(&db, "SELECT * FROM registrations ORDER BY t DESC LIMIT 500",  vec![]).await;
            let tg_rows     = d1_rows(&db, "SELECT * FROM tg_links      ORDER BY t DESC LIMIT 500",  vec![]).await;

            let visits:        Vec<Visit>        = visit_rows.iter().map(row_to_visit).collect();
            let purchases:     Vec<Purchase>     = pur_rows.iter().map(row_to_purchase).collect();
            let registrations: Vec<Registration> = reg_rows.iter().map(row_to_registration).collect();
            let tg_links:      Vec<TgLink>       = tg_rows.iter().map(row_to_tg).collect();

            let mut stats = Stats {
                total:     visits.len(),
                purchases: purchases.len(),
                revenue:   purchases.iter().map(|p| p.amount).sum(),
                countries: HashMap::new(),
                devices:   HashMap::new(),
                sources:   HashMap::new(),
            };
            for v in &visits {
                *stats.countries.entry(v.co.clone()).or_insert(0) += 1;
                *stats.devices.entry(v.d.clone()).or_insert(0) += 1;
                let src = if !v.s.is_empty() { v.s.clone() }
                          else if !v.rf.is_empty() { source_from_ref(&v.rf) }
                          else { "Direct".into() };
                *stats.sources.entry(src).or_insert(0) += 1;
            }

            Response::from_json(&ApiResp { stats, visits, purchases, registrations, tg_links })
        }

        // /api/delete — удаляет запись(и) из таблицы (visits или tg_links)
        "/api/delete" => {
            if req.method() != Method::Post {
                return Response::error("Method Not Allowed", 405);
            }
            let body: serde_json::Value = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            if body.get("key").and_then(|v| v.as_str()).unwrap_or("") != analytics_key {
                return Response::error("Unauthorized", 401);
            }
            let table = match body.get("table").and_then(|v| v.as_str()) {
                Some(t) if t == "visits" || t == "tg_links" || t == "purchases" || t == "registrations" => t,
                _ => return Response::error("Bad Request", 400),
            };
            let all = body.get("all").and_then(|v| v.as_bool()).unwrap_or(false);
            if all {
                let sql = match table {
                    "visits"        => "DELETE FROM visits",
                    "purchases"     => "DELETE FROM purchases",
                    "registrations" => "DELETE FROM registrations",
                    "tg_links"      => "DELETE FROM tg_links",
                    _               => return Response::error("Bad Request", 400),
                };
                d1_exec(&db, sql, vec![]).await;
            } else {
                let id = match body.get("id").and_then(|v| v.as_i64()) {
                    Some(i) => i,
                    None => return Response::error("Bad Request", 400),
                };
                let sql = match table {
                    "visits"        => "DELETE FROM visits WHERE id=?",
                    "purchases"     => "DELETE FROM purchases WHERE id=?",
                    "registrations" => "DELETE FROM registrations WHERE id=?",
                    "tg_links"      => "DELETE FROM tg_links WHERE id=?",
                    _               => return Response::error("Bad Request", 400),
                };
                d1_exec(&db, sql, vec![JsValue::from_f64(id as f64)]).await;
            }
            Response::from_json(&serde_json::json!({"ok": true}))
        }

        // /health — проверка работоспособности воркера (возвращает "ok")
        "/api/tg_check" => {
            let key = url.query_pairs()
                .find(|(k, _)| k == "key")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            if key != analytics_key {
                return Response::error("Unauthorized", 401);
            }
            let tg_id_str = url.query_pairs()
                .find(|(k, _)| k == "tg_id")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let tg_id: i64 = tg_id_str.parse().unwrap_or(0);
            if tg_id == 0 {
                return Response::from_json(&serde_json::json!({"verified": false}));
            }
            let rows = d1_rows(&db,
                "SELECT id, ok_mid FROM tg_links WHERE tg_id = ? LIMIT 1",
                vec![JsValue::from_f64(tg_id as f64)],
            ).await;
            let verified = !rows.is_empty();
            let ok_mid = rows.first().and_then(|r| r.get("ok_mid")).and_then(|v| v.as_i64()).unwrap_or(0);
            Response::from_json(&serde_json::json!({"verified": verified, "ok_mid": ok_mid}))
        }

        "/app" => {
            let html = format!(r#"<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Проверка</title>
<script src="https://telegram.org/js/telegram-web-app.js"></script>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{background:#0f0f13;color:#fff;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;text-align:center;padding:20px}}
.card{{max-width:360px;width:100%}}
.check{{width:72px;height:72px;background:linear-gradient(135deg,#2AABEE,#229ED9);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 24px;font-size:36px;animation:pop .4s ease}}
@keyframes pop{{0%{{transform:scale(0)}}70%{{transform:scale(1.15)}}100%{{transform:scale(1)}}}}
h1{{font-size:22px;font-weight:700;margin-bottom:10px}}
p{{color:#aaa;font-size:15px;line-height:1.5;margin-bottom:28px}}
.spinner{{width:40px;height:40px;border:3px solid #333;border-top-color:#2AABEE;border-radius:50%;animation:spin 0.8s linear infinite;margin:0 auto}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head>
<body>
<div class="card">
  <div class="check">✅</div>
  <h1>Проверка пройдена!</h1>
  <p id="msg">Подождите...</p>
  <div class="spinner" id="sp"></div>
</div>
<script>
var tg = window.Telegram.WebApp;
tg.ready();
tg.expand();

// Получаем cookie _vid
function getCookie(name) {{
  var v = document.cookie.match('(^|;) ?'+name+'=([^;]*)(;|$)');
  return v ? v[2] : '';
}}

var initData = tg.initData;
var vid = getCookie('_vid');

if (!initData) {{
  document.getElementById('msg').textContent = 'Ошибка: нет данных Telegram';
  document.getElementById('sp').style.display = 'none';
}} else {{
  fetch('/api/webapp_verify', {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{
      init_data: initData,
      vid: vid
    }})
  }})
  .then(function(r) {{ return r.json(); }})
  .then(function(d) {{
    document.getElementById('sp').style.display = 'none';
    if (d.ok) {{
      document.getElementById('msg').textContent = 'Возвращаемся в Telegram...';
      setTimeout(function() {{ tg.close(); }}, 1000);
    }} else {{
      document.getElementById('msg').textContent = 'Ошибка: ' + (d.error || 'неизвестная');
    }}
  }})
  .catch(function(e) {{
    document.getElementById('sp').style.display = 'none';
    document.getElementById('msg').textContent = 'Ошибка соединения';
  }});
}}
</script>
</body>
</html>"#);
            let mut resp = Response::from_html(&html)?;
            resp.headers_mut().set("Content-Type", "text/html; charset=utf-8")?;
            Ok(resp)
        }

        "/api/webapp_verify" => {
            if req.method() != Method::Post {
                return Response::error("Method Not Allowed", 405);
            }
            #[derive(Deserialize)]
            struct WebAppReq {
                init_data: String,
                #[serde(default)]
                vid: String,
            }
            let body: WebAppReq = match req.json().await {
                Ok(b) => b,
                Err(_) => return Response::error("Bad Request", 400),
            };
            // Верифицируем initData через HMAC-SHA256 — это и есть авторизация
            let bot_token_verify = env.secret("BOT_TOKEN").map(|v| v.to_string()).unwrap_or_default();
            if !verify_webapp_init_data(&body.init_data, &bot_token_verify) {
                return Response::from_json(&serde_json::json!({"ok": false, "error": "invalid init_data"}));
            }
            // Парсим tg_id, имя и username из initData
            let tg_id = parse_tg_id_from_init_data(&body.init_data);
            if tg_id == 0 {
                return Response::from_json(&serde_json::json!({"ok": false, "error": "no tg_id"}));
            }
            let (tg_user, tg_name) = parse_tg_user_from_init_data(&body.init_data);
            let now = Date::now().as_millis() as i64;
            // Ищем vid: cookie → UA+страна за 30 минут
            let fp_ua = hdr(req.headers(), "user-agent");
            let fp_co = req.cf().as_ref().and_then(|cf| cf.country()).unwrap_or_default();
            let cutoff_30m = now - 30 * 60 * 1000;

            let vid = if !body.vid.is_empty() {
                // Уровень 1: cookie
                let rows = d1_rows(&db,
                    "SELECT vid FROM visits WHERE vid = ? LIMIT 1",
                    vec![JsValue::from_str(&body.vid)],
                ).await;
                rows.first().and_then(|r| r.get("vid")).and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else if !fp_co.is_empty() {
                // Уровень 2: устройство (Android/iPhone) + страна за последние 30 минут
                // UA в Mini App отличается от UA в браузере, поэтому ищем по d (тип девайса)
                let fp_device = device(&fp_ua);
                // Берём только платформу: Android или iPhone
                let platform = if fp_device.contains("Android") { "Android" }
                    else if fp_device.contains("iPhone") { "iPhone" }
                    else { "" };
                let rows = if !platform.is_empty() {
                    d1_rows(&db,
                        "SELECT vid FROM visits WHERE d LIKE ? AND co = ? AND vid != '' AND t > ? ORDER BY t DESC LIMIT 1",
                        vec![
                            JsValue::from_str(&format!("%{}%", platform)),
                            JsValue::from_str(&fp_co),
                            JsValue::from_f64(cutoff_30m as f64),
                        ],
                    ).await
                } else { vec![] };
                rows.first().and_then(|r| r.get("vid")).and_then(|v| v.as_str()).unwrap_or("").to_string()
            } else {
                String::new()
            };
            d1_exec(&db,
                "INSERT INTO tg_links (t, vid, tg_id, tg_user, tg_name) VALUES (?, ?, ?, ?, ?) ON CONFLICT(tg_id) DO UPDATE SET t=excluded.t, vid=CASE WHEN excluded.vid != '' THEN excluded.vid ELSE tg_links.vid END, tg_user=CASE WHEN excluded.tg_user != '' THEN excluded.tg_user ELSE tg_links.tg_user END, tg_name=CASE WHEN excluded.tg_name != '' THEN excluded.tg_name ELSE tg_links.tg_name END",
                vec![
                    JsValue::from_f64(now as f64),
                    JsValue::from_str(&vid),
                    JsValue::from_f64(tg_id as f64),
                    JsValue::from_str(&tg_user),
                    JsValue::from_str(&tg_name),
                ],
            ).await;
            // Отправляем сообщение в бот и сохраняем ok_mid
            let bot_token2 = env.secret("BOT_TOKEN").map(|v| v.to_string()).unwrap_or_default();
            if !bot_token2.is_empty() {
                #[derive(Serialize)]
                struct TgMsg { chat_id: i64, text: &'static str, parse_mode: &'static str }
                let msg = TgMsg { chat_id: tg_id, text: "✅ Проверка пройдена! Нажмите /start чтобы продолжить.", parse_mode: "HTML" };
                if let Ok(body_str) = serde_json::to_string(&msg) {
                    let headers = Headers::new();
                    let _ = headers.set("Content-Type", "application/json");
                    let mut init = RequestInit::new();
                    init.with_method(Method::Post).with_headers(headers).with_body(Some(JsValue::from_str(&body_str)));
                    let tg_url = format!("https://api.telegram.org/bot{}/sendMessage", bot_token2);
                    if let Ok(tg_req) = Request::new_with_init(&tg_url, &init) {
                        if let Ok(mut tg_resp) = Fetch::Request(tg_req).send().await {
                            if let Ok(tg_text) = tg_resp.text().await {
                                let ok_mid = serde_json::from_str::<serde_json::Value>(&tg_text)
                                    .ok()
                                    .and_then(|v| v["result"]["message_id"].as_i64())
                                    .unwrap_or(0);
                                if ok_mid > 0 {
                                    d1_exec(&db,
                                        "UPDATE tg_links SET ok_mid = ? WHERE tg_id = ?",
                                        vec![
                                            JsValue::from_f64(ok_mid as f64),
                                            JsValue::from_f64(tg_id as f64),
                                        ],
                                    ).await;
                                }
                            }
                        }
                    }
                }
            }
            Response::from_json(&serde_json::json!({"ok": true}))
        }

        "/health" => Response::ok("ok"),

        // /* — главный обработчик: любой другой путь = новый визит
        _ => {
            // Игнорируем служебные файлы
            if path == "/favicon.ico" || path == "/robots.txt"
                || path.ends_with(".png") || path.ends_with(".ico")
                || path.ends_with(".js") || path.ends_with(".css") {
                return Response::error("Not Found", 404)
            }
            // Читаем заголовки запроса
            let headers = req.headers();
            let ua  = hdr(headers, "user-agent");   // браузер/устройство
            let rf  = hdr(headers, "referer");       // откуда пришёл
            let ip  = hdr(headers, "cf-connecting-ip"); // IP адрес
            let salt = env.secret("SALT").map(|v| v.to_string()).unwrap_or_default();
            let lang = hdr(headers, "accept-language").chars().take(20).collect::<String>();
            let platform = hdr(headers, "sec-ch-ua-platform").trim_matches('"').to_string();
            let asn = req.cf().as_ref().and_then(|cf| cf.as_organization()).unwrap_or_default();
            // Читаем cookie_id из куки или генерируем новый
            let cookie_header = hdr(headers, "cookie");
            let existing_cookie = cookie_header.split(';').find_map(|part| {
                let p = part.trim();
                p.strip_prefix("_vid=").map(|v| v.to_string())
            }).unwrap_or_default();
            let cookie_id = if !existing_cookie.is_empty() { existing_cookie.clone() } else { rand_hex(8) };

            // Геолокация через Cloudflare (страна и город)
            let co = req.cf().as_ref().and_then(|cf| cf.country()).unwrap_or_else(|| "??".into());
            let ci = req.cf().as_ref().and_then(|cf| cf.city()).unwrap_or_else(|| "??".into());

            // Гео-блокировка — заблокированные страны получают страницу "недоступно"
            const BLOCKED_GEO: &[&str] = &["US", "CN", "KR", "DE", "JP", "IE", "SE"];
            if BLOCKED_GEO.contains(&co.as_str()) {
                return Response::from_html(r#"<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Недоступно</title><style>body{margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f0f0f;font-family:sans-serif;color:#fff}div{text-align:center;padding:2rem}.icon{font-size:3rem;margin-bottom:1rem}.title{font-size:1.4rem;font-weight:600;margin-bottom:.5rem}.sub{color:#888;font-size:.95rem}</style></head><body><div><div class="icon">🚫</div><div class="title">Контент недоступен</div><div class="sub">Этот сайт недоступен в вашем регионе.</div></div></body></html>"#);
            }

            // Читаем параметры из URL
            let fbclid = url.query_pairs()
                .find(|(k, _)| k == "fbclid")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let utm_c = url.query_pairs()
                .find(|(k, _)| k == "utm_campaign")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let utm_ct = url.query_pairs()
                .find(|(k, _)| k == "utm_content")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            let utm_as = url.query_pairs()
                .find(|(k, _)| k == "utm_adset" || k == "utm_term")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            // ?s=t/tt/fb/ig/... — короткий параметр источника
            let src_param = url.query_pairs()
                .find(|(k, _)| k == "s")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();
            // ?utm_source=... — стандартный UTM параметр источника
            let utm_source = url.query_pairs()
                .find(|(k, _)| k == "utm_source")
                .map(|(_, v)| v.to_string())
                .unwrap_or_default();

            // Определяем источник трафика (приоритет: ?s= > utm_source > referer)
            let source = if !src_param.is_empty() {
                match src_param.as_str() {
                    "tt_ubt" => "TikTok UBT".into(),
                    "fb_ads" => "Facebook Ads".into(),
                    "fb"  => "Facebook".into(),
                    "ig"  => "Instagram".into(),
                    "t"   => "TikTok".into(),
                    "tt"  => "TikTok".into(),
                    "yt"  => "YouTube".into(),
                    "tg"  => "Telegram".into(),
                    "tw"  => "Twitter".into(),
                    "go"  => "Google".into(),
                    other => other.to_string(),
                }
            } else if !utm_source.is_empty() {
                match utm_source.to_lowercase().as_str() {
                    s if s == "tt_ubt"                              => "TikTok UBT".into(),
                    s if s == "fb_ads"                              => "Facebook Ads".into(),
                    s if s.contains("facebook") || s.contains("fb") => "Facebook".into(),
                    s if s.contains("instagram") || s == "ig"       => "Instagram".into(),
                    s if s.contains("tiktok") || s == "tt"          => "TikTok".into(),
                    s if s.contains("youtube") || s == "yt"         => "YouTube".into(),
                    s if s.contains("telegram") || s == "tg"        => "Telegram".into(),
                    s if s.contains("twitter") || s == "tw"         => "Twitter".into(),
                    s if s.contains("google") || s == "go"          => "Google".into(),
                    other => other.to_string(),
                }
            } else if !fbclid.is_empty() {
                "Facebook Ads".into()
            } else {
                source_from_ref(&rf)
            };

            // Фильтр ботов — не пишем в БД, отдаём пустой 200
            if is_bot(&ua) {
                return Response::ok("");
            }

            let now = Date::now().as_millis() as i64;
            let h = hash_ip(&ip, &salt);
            let ua_trunc: String = ua.chars().take(255).collect();
            let rf_trunc: String = rf.chars().take(255).collect();
            let fbclid_trunc: String = fbclid.chars().take(100).collect();

            // Генерируем vid заранее — случайный hex, уникальный, без race condition
            let vid = rand_hex(6);

            // Сохраняем визит в D1 с готовым vid
            d1_exec(&db,
                "INSERT INTO visits (t, h, co, ci, d, s, rf, fbclid, utm_c, utm_ct, utm_as, ua, vid, cookie_id, asn, lang, platform) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                vec![
                    JsValue::from_f64(now as f64),
                    JsValue::from_str(&h),
                    JsValue::from_str(&co),
                    JsValue::from_str(&ci),
                    JsValue::from_str(&device(&ua)),
                    JsValue::from_str(&source),
                    JsValue::from_str(&rf_trunc),
                    JsValue::from_str(&fbclid_trunc),
                    JsValue::from_str(&utm_c),
                    JsValue::from_str(&utm_ct),
                    JsValue::from_str(&utm_as),
                    JsValue::from_str(&ua_trunc),
                    JsValue::from_str(&vid),
                    JsValue::from_str(&cookie_id),
                    JsValue::from_str(&asn),
                    JsValue::from_str(&lang),
                    JsValue::from_str(&platform),
                ],
            ).await;

            let pixel_id = env.var("FB_PIXEL_ID").map(|v| v.to_string()).unwrap_or_default();
            let token = env.secret("FB_ACCESS_TOKEN").map(|v| v.to_string()).unwrap_or_default();
            let test_code = env.var("FB_TEST_CODE").map(|v| v.to_string()).unwrap_or_default();

            // Если пришёл с ФБ рекламы (есть fbclid) — отправляем PageView в CAPI с сервера
            // Используем wait_until чтобы не блокировать ответ пользователю (~300-500ms)
            if !fbclid.is_empty() && !pixel_id.is_empty() && !token.is_empty() {
                let (pv_pixel, pv_token, pv_test, pv_fbc, pv_ua) =
                    (pixel_id.clone(), token.clone(), test_code.clone(), fbclid.clone(), ua.clone());
                ctx.wait_until(async move {
                    send_capi_pageview(pv_pixel, pv_token, pv_test, pv_fbc, pv_ua, now).await;
                });
            }

            // Формируем ссылку на бота с vid (например t.me/HDevaBot?start=1002)
            let bot = env.var("TG_BOT").map(|v| v.to_string()).unwrap_or_default();
            let tg_url = if !bot.is_empty() {
                format!("https://t.me/{}?start={}", bot, vid)
            } else {
                "https://t.me".to_string()
            };

            // Если настроен пиксель — показываем промежуточную страницу:
            // 1. Загружает FB пиксель и отправляет PageView (браузерная сторона)
            // 2. Через 1.5 секунды делает редирект в бота
            // Это обеспечивает двойное отслеживание: пиксель (браузер) + CAPI (сервер)
            if !pixel_id.is_empty() {
                let event_id = rand_hex(8);
                let fbc_val = if !fbclid.is_empty() {
                    format!("fb.1.{}.{}", now / 1000, fbclid)
                } else {
                    String::new()
                };
                let test_code_js = if !test_code.is_empty() {
                    format!("fbq('set','testEventCode','{}');", test_code)
                } else {
                    String::new()
                };
                let html = format!(
                    r#"<!DOCTYPE html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>*{{margin:0;padding:0}}body{{background:#000;display:flex;align-items:center;justify-content:center;min-height:100vh}}.sp{{width:36px;height:36px;border:3px solid #333;border-top-color:#3b82f6;border-radius:50%;animation:spin 0.8s linear infinite}}@keyframes spin{{to{{transform:rotate(360deg)}}}}</style></head><body><div class="sp"></div><script>!function(f,b,e,v,n,t,s){{if(f.fbq)return;n=f.fbq=function(){{n.callMethod?n.callMethod.apply(n,arguments):n.queue.push(arguments)}};if(!f._fbq)f._fbq=n;n.push=n;n.loaded=!0;n.version='2.0';n.queue=[];t=b.createElement(e);t.async=!0;t.src=v;s=b.getElementsByTagName(e)[0];s.parentNode.insertBefore(t,s)}}(window,document,'script','https://connect.facebook.net/en_US/fbevents.js');fbq('init','{pixel_id}');{test_code_js}fbq('track','PageView',{{fbc:'{fbc_val}'}},{{eventID:'{event_id}'}});setTimeout(function(){{location.replace('{tg_url}')}},900);</script><noscript><img height="1" width="1" style="display:none" src="https://www.facebook.com/tr?id={pixel_id}&ev=PageView&noscript=1"/></noscript></body></html>"#,
                    pixel_id = pixel_id,
                    fbc_val = fbc_val,
                    test_code_js = test_code_js,
                    event_id = event_id,
                    tg_url = tg_url,
                );
               let mut resp = Response::from_html(&html)?;
                resp.headers_mut().set("Cache-Control", "no-store")?;
                resp.headers_mut().set("Set-Cookie", &format!("_vid={}; Path=/; Max-Age=604800; SameSite=Lax", vid))?;
                Ok(resp)
            } else {
                // Если пиксель не настроен — просто редирект в бота
                Response::redirect(url::Url::parse(&tg_url)?)
            }
        }
    }
}
