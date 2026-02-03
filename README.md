
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
//deactivate

pip install -r requirements.txt
flask db upgrade
python app.py
```

Backend runs on: `http://127.0.0.1:5000`

### 2. Frontend Setup (New Terminal)

```powershell
cd frontend
npm install
npm start
```

Frontend runs on: `http://localhost:3000`

### 3. Login

Visit `http://localhost:3000` and login with:
- **Username**: `admin`
- **Password**: `admin123`

//inbound & outbound
ping <IP_ADDRESS>
Test-NetConnection <IP_ADDRESS> -Port 443

