# Рабочие ссылки comedownl.shop

## TikTok
```
https://comedownl.shop/?s=t
```

## Facebook Ads
```
https://comedownl.shop/?s=fb_ads&utm_campaign=КАМПАНИЯ&utm_adset=ГРУППА
```
> fbclid FB добавит автоматически при клике с рекламы

---

## Dashboard
```
https://comedownl.shop/analytics
```
login: viasef
pass: s%s&hQExT@zb%Cp~@i7F

---

## API (внутреннее)

| Endpoint | Метод | Описание |
|---|---|---|
| `/?s=...&utm_campaign=...` | GET | Трекинг визита → редирект в TG |
| `/analytics` | GET | Dashboard (cookie auth) |
| `/analytics/login` | POST | `{l, p}` → cookie |
| `/api/stats?key=KEY` | GET | Все данные |
| `/api/purchase` | POST | `{key, fbclid, amount, currency, visit_t, ua, utm_c}` |
| `/api/tg` | POST | `{key, vid, tg_id, tg_user, tg_name}` |

ANALYTICS_KEY: `21njKadew4ufFuejfbfvjr`
