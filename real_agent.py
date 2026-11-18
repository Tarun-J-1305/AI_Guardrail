import os
from google import genai
from guardrail import GuardrailProxy

# Initialize your Security Firewall
proxy = GuardrailProxy()

# Wrap your tools so EVERY AI call goes through GuardrailProxy
def read_file(filename: str) -> str:
    """Reads the contents of a text file from the workspace."""
    return proxy.execute_tool("read_file", filename=filename)

def send_email(to: str, content: str) -> str:
    """Sends an email to a recipient with the given content."""
    return proxy.execute_tool("send_email", to=to, content=content)

# Connect to Gemini using a Chat session (cleanest way to handle tools)
client = genai.Client()
chat = client.chats.create(
    model="gemini-3.5-flash-lite",
    config={"tools": [read_file, send_email]},
)

print("=== STARTING REAL AI AGENT WITH GUARDRAIL MIDDLEWARE ===\n")
user_prompt = "Please read feedback.txt and give me a quick summary of what the customer said."
print(f"User Prompt: {user_prompt}\n")

response = chat.send_message(user_prompt)

print("\n=== FINAL AI RESPONSE ===")
print(response.text)
