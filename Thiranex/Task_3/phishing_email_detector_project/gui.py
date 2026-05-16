import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from detector import analyze_text

def launch_app():
    root = tk.Tk()
    root.title("Phishing Email Detector")
    root.geometry("900x650")

    ttk.Label(root, text="Paste Email Content:", font=("Arial", 14, "bold")).pack(pady=5)

    text = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=20)
    text.pack(fill="both", expand=True, padx=10, pady=10)

    result = scrolledtext.ScrolledText(root, wrap=tk.WORD, height=10, state="normal")
    result.pack(fill="both", expand=False, padx=10, pady=10)

    def detect():
        content = text.get("1.0", tk.END).strip()
        if not content:
            messagebox.showwarning("Input Required", "Please paste email content.")
            return
        analysis = analyze_text(content)
        result.delete("1.0", tk.END)
        result.insert(tk.END, f"Verdict: {analysis['label']}\n")
        result.insert(tk.END, f"Confidence: {analysis['confidence']}%\n")
        result.insert(tk.END, f"Risk Score: {analysis['score']}\n\nReasons:\n")
        for reason in analysis["reasons"]:
            result.insert(tk.END, f"- {reason}\n")

    ttk.Button(root, text="Detect Email", command=detect).pack(pady=10)

    root.mainloop()
