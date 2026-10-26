# LLM-Based Phishing Email Detection (Groq Edition)

This project detects whether an `.eml` email is **phishing** or
**legitimate** using a Groq-hosted large language model. It is adapted
from the original ChatSpamDetector journal paper and re-targeted at Groq's OpenAI-compatible API.

---

## 1. Project Structure
Ananya_J_263IS001/
├── detect.py # CLI entry point: prompt, API call, validation, logging
├── email_processor.py # Email canonicalization + token-budget trimming (email preprocessing)
├── requirements.txt # Python dependencies
├── .env.example # Template for environment variables
├── .env # Your local secrets (create this, do NOT commit)
├── sample.eml # The email you want to analyze (Shld be named as sample.eml)
└── logs/ # Created automatically after a run

---

## 2. Setup 
Copy the whole project folder (or clone it) and open a terminal inside it
In  terminal run (once):
>>python -m venv .venv
>>.venv\Scripts\activate
>>python -m pip install -U pip
>>python -m pip install -r requirements.txt

Create .env file
>>copy .env.example .env  (or)  Copy-Item .env.example .env
Open .env and paste your real Groq key:
GROQ_API_KEY=gsk_your_real_key_here
GROQ_MODEL=openai/gpt-oss-120b

Save Save the email you want to test as sample.eml in the project root 
Gmail: open the email → three-dot menu → Download message.

Command to run the project:
>>python detect.py --normal sample.eml

All commands:
>>python detect.py --help

---

## By default, logs are written to logs/
prompt.txt	    Full system + user prompt sent to the model
response.json	Raw Groq API response
result.json  	Parsed and validated result
log.json	    Timestamps, elapsed time, attempts, error (if any)