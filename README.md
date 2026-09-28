# TruthLens - AI Data Forensics Platform

Upload any CSV and TruthLens audits whether the data can be trusted. It produces a 0-100 Trust Score and flags:
- **Fabricated / manipulated numbers** (Benford's law chi-square test on first digits)
- **Target leakage** (features that secretly encode the label)
- **Bias** (disparate impact / four-fifths rule across a sensitive column)
- Duplicates, missing values, extreme outliers, round-number heaping, constant and ID-like columns
- Optional plain-English audit summary from Gemini (free key)

## Run locally
```
python -m venv venv
venv\Scripts\activate          (Mac/Linux: source venv/bin/activate)
pip install -r requirements.txt
uvicorn api.index:app --reload
```
Open http://localhost:8000 and click "Load flawed demo data" (or upload `sample_data.csv`).

## GitHub
```
git init
git add .
git commit -m "Initial commit: TruthLens"
git branch -M main
git remote add origin https://github.com/YOUR-USERNAME/truthlens.git
git push -u origin main
```

## Deploy to Vercel
Import the repo at vercel.com/new and click Deploy, or:
```
npm i -g vercel
vercel login
vercel --prod
```
Optional: add `GEMINI_API_KEY` (free at aistudio.google.com) in Vercel > Settings > Environment Variables.
Limit: Vercel accepts request bodies up to ~4.5 MB, so use CSV files below that size.
