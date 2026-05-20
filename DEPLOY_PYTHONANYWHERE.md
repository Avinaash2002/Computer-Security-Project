# Deploying SecureAuth on PythonAnywhere — Step by Step

## Step 1: Create Account
Go to https://www.pythonanywhere.com and sign up for a **free** account.
Your site will be at: `yourusername.pythonanywhere.com`

---

## Step 2: Upload Your Project Files

### Option A: Upload via GitHub (Recommended)
1. Push your `project/` folder to a GitHub repository
2. On PythonAnywhere, open a **Bash console** (Dashboard → Consoles → Bash)
3. Run:
```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/YOUR_REPO_NAME.git project
```

### Option B: Upload Manually
1. Go to the **Files** tab on PythonAnywhere
2. Navigate to `/home/yourusername/`
3. Create a folder called `project`
4. Upload ALL files into `/home/yourusername/project/`:
   - app.py
   - train_model.py
   - requirements.txt
5. Create subfolders and upload:
   - `templates/` → all 5 HTML files
   - `static/` → style.css
   - `ml_model/` → risk_model.pkl, decision_tree_model.pkl, training_data.csv

---

## Step 3: Set Up Virtual Environment

Open a **Bash console** and run these commands one by one:

```bash
cd ~
mkvirtualenv --python=/usr/bin/python3.10 secureauth
pip install flask flask-mail scikit-learn numpy pandas
```

---

## Step 4: Train the ML Model

In the same Bash console:

```bash
cd ~/project
python train_model.py
```

You should see the training output with ~97% accuracy.

---

## Step 5: Configure Email

Edit app.py on PythonAnywhere (Files tab → project/app.py → click to edit):

Change these 3 lines:
```
app.config['MAIL_USERNAME'] = 'your_real_email@gmail.com'
app.config['MAIL_PASSWORD'] = 'xxxx xxxx xxxx xxxx'
app.config['MAIL_DEFAULT_SENDER'] = ('SecureAuth MFA', 'your_real_email@gmail.com')
```

Also edit `users.json` and change the email addresses to real ones.

NOTE: PythonAnywhere free accounts ONLY support Gmail SMTP.
Other email providers (Outlook, Yahoo) will NOT work on the free tier.

---

## Step 6: Create Web App

1. Go to the **Web** tab
2. Click **"Add a new web app"**
3. Click **Next** (accept yourusername.pythonanywhere.com)
4. Select **"Manual configuration"** (NOT "Flask" — choose Manual)
5. Select **Python 3.10**
6. Click **Next**

---

## Step 7: Configure the Web App

On the Web tab, you will see your web app settings. Configure these:

### A. Source Code
Set to:
```
/home/yourusername/project
```

### B. Virtualenv
In the "Virtualenv" section, enter:
```
/home/yourusername/.virtualenvs/secureauth
```

### C. WSGI File
Click the link to the **WSGI configuration file** (looks like:
`/var/www/yourusername_pythonanywhere_com_wsgi.py`)

**Delete everything** in that file and replace with:

```python
import sys
import os

project_path = '/home/yourusername/project'

if project_path not in sys.path:
    sys.path.insert(0, project_path)

os.chdir(project_path)

from app import app as application
```

**IMPORTANT: Replace `yourusername` with your actual PythonAnywhere username in BOTH places.**

Click **Save**.

### D. Static Files
Scroll down to the **Static files** section and add:
- URL: `/static/`
- Directory: `/home/yourusername/project/static`

---

## Step 8: Reload and Visit

1. Go back to the **Web** tab
2. Click the green **"Reload"** button
3. Visit: `https://yourusername.pythonanywhere.com`

Your app should be live!

---

## Troubleshooting

### "Something went wrong" error page
→ Web tab → click **Error log** → check last few lines
→ Most common: wrong username in WSGI file paths

### "Module not found" errors
→ Bash console:
```bash
workon secureauth
pip install flask flask-mail scikit-learn numpy pandas
```
→ Then Reload web app

### ML model not loading
→ Bash console:
```bash
cd ~/project
workon secureauth
python train_model.py
```
→ Then Reload web app

### CSS not loading (unstyled page)
→ Web tab → Static files section → make sure you added:
   URL: `/static/`  Directory: `/home/yourusername/project/static`

### Email not sending
→ Only Gmail works on free accounts
→ Must use App Password not regular password
→ If it fails, OTP prints in Error log (check it there)
