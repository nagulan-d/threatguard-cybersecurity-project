
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
//deactivate

pip install -r requirements.txt
flask db upgrade

# ⚠️ IMPORTANT: Run as Administrator for IP Blocking!
# The backend needs admin privileges to create Windows Firewall rules
# Right-click PowerShell -> "Run as Administrator", then run:
python app.py

# Or use the admin startup script:
# .\START_BACKEND_ADMIN.ps1
```

Backend runs on: `http://127.0.0.1:5000`

Deployment guide: readme/DEPLOYMENT_GUIDE.md

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

