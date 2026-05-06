# savdo.uz — Aqlli Boshqaruv Tizimi

Kirim-chiqim boshqaruv tizimi. FastAPI backend + SQLite baza.

## Login

- **Login:** `admin`
- **Parol:** `admin123`

## Texnologiyalar

- **Backend:** FastAPI (Python)
- **Baza:** SQLite
- **Frontend:** Vanilla HTML/CSS/JS
- **Auth:** JWT token

## Lokal ishga tushirish

```bash
pip install -e .
uvicorn main:app --reload
```

http://localhost:8000 da ochiladi.

## Deploy (Railway)

1. GitHub repoga push qiling
2. Railway.app da "New Project" → "Deploy from GitHub repo"
3. Repo tanlang — avtomatik deploy bo'ladi
