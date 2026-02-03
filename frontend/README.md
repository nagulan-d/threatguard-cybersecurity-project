# Frontend (ThreatGuard UI)

React 18 single-page app for ThreatGuard. Uses React Router, Framer Motion, and a centralized API config.

## Environment

Copy `.env.example` to `.env` and set the backend origin:

```
REACT_APP_API_ORIGIN=http://127.0.0.1:5000
```

## Scripts

- `npm start`: Start dev server at http://localhost:3000
- `npm run build`: Build production assets to `build/`

## Notes

- API origin is read from `REACT_APP_API_ORIGIN` and composed in `src/config.js`.
- Avoid hardcoding URLs; import `API_URL` or `API_ORIGIN` from `src/config.js`.
- Axios instance is defined in `src/api.js` if you prefer that style.

## Docker (optional)

From repo root:

```
docker compose up --build frontend
```
