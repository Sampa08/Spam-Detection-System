from flask import Flask, request
import json

app = Flask(__name__)

SMS_PATH = "latest_sms.json"

@app.route("/sms", methods=["POST"])
def sms_webhook():
    sms_text = request.form.get("Body", "")
    from_number = request.form.get("From", "")
    # Save SMS to file for your Tkinter app to read
    with open(SMS_PATH, "w", encoding="utf-8") as f:
        json.dump({"from": from_number, "text": sms_text}, f)
    return "OK", 200

if __name__ == "__main__":
    app.run(port=5000)