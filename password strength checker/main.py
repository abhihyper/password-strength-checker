import re
import string
import getpass
from collections import Counter
from time import perf_counter

class PasswordStrengthChecker:
    def __init__(self, password):
        self.password = password
        self.length = len(password)
        self.score = 0
        self.feedback = []
        self.common_passwords = self.load_common_passwords()

    def load_common_passwords(self):
        try:
            with open('common_passwords.txt', 'r') as f:
                return set(line.strip() for line in f)
        except FileNotFoundError:
            return {'password', '123456', 'qwerty', 'abc123', 'admin', 'welcome'}

    def check_length(self):
        if self.length < 8:
            self.feedback.append("Password is too short (min 8 characters).")
            return 0
        elif self.length < 12:
            self.feedback.append("Length is okay but could be longer.")
            return 2
        elif self.length < 16:
            self.feedback.append("Good password length.")
            return 3
        else:
            self.feedback.append("Excellent password length.")
            return 4

    def check_character_types(self):
        types = sum([
            any(c.islower() for c in self.password),
            any(c.isupper() for c in self.password),
            any(c.isdigit() for c in self.password),
            any(c in string.punctuation for c in self.password)
        ])
        if types < 3:
            self.feedback.append("Use a mix of upper, lower, digits, and special chars.")
        return types

    def check_common_patterns(self):
        bad_patterns = ['123', 'abc', 'qwerty']
        lowered = self.password.lower()
        if any(pat in lowered for pat in bad_patterns):
            self.feedback.append("Avoid common patterns like '123', 'abc', 'qwerty'.")
            return -2
        return 0

    def check_common_password(self):
        if self.password.lower() in self.common_passwords:
            self.feedback.append("This password is too common!")
            return -2
        return 0

    def calculate_entropy(self):
        charset_size = 0
        charset_size += 26 if any(c.islower() for c in self.password) else 0
        charset_size += 26 if any(c.isupper() for c in self.password) else 0
        charset_size += 10 if any(c.isdigit() for c in self.password) else 0
        charset_size += 32 if any(c in string.punctuation for c in self.password) else 0
        return self.length * (charset_size ** 0.5) if charset_size else 0

    def estimate_crack_time(self, entropy):
        guesses = (2 ** entropy) / 2
        seconds = guesses / 1e12
        if seconds < 60:
            return "less than a minute"
        elif seconds < 3600:
            return f"{int(seconds/60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds/3600)} hours"
        else:
            return f"{int(seconds/86400)} days"

    def evaluate(self):
        start = perf_counter()
        self.score += self.check_length()
        self.score += self.check_character_types()
        self.score += self.check_common_patterns()
        self.score += self.check_common_password()
        entropy = self.calculate_entropy()
        self.score += min(int(entropy / 20), 5)

        rating = ["Very Weak", "Weak", "Moderate", "Strong", "Very Strong"]
        final_rating = rating[min(self.score // 3, 4)]

        crack_time = self.estimate_crack_time(entropy)
        elapsed = perf_counter() - start

        return {
            "rating": final_rating,
            "score": self.score,
            "entropy": round(entropy, 1),
            "crack_time": crack_time,
            "feedback": self.feedback,
            "time_taken": round(elapsed, 4)
        }

def simple_strength_check(password):
    if len(password) < 8:
        return "Weak"
    if not re.search(r"[a-z]", password):
        return "Weak"
    if not re.search(r"[A-Z]", password):
        return "Weak"
    if not re.search(r"\d", password):
        return "Weak"
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return "Weak"
    if len(password) < 12:
        return "Moderate"
    return "Strong"

def main():
    print("Password Strength Checker\n(Type 'quit' to exit)\n")
    while True:
        password = input("Enter Password: ")
        if password.lower() == 'quit':
            print("\nThank you for using Password Strength Checker!")
            break

        # Full detailed evaluation
        checker = PasswordStrengthChecker(password)
        result = checker.evaluate()

        # Simple quick check
        simple_result = simple_strength_check(password)

        print("\n--- Detailed Evaluation ---")
        print(f"Rating: {result['rating']}")
        print(f"Score: {result['score']}/15")
        print(f"Entropy: {result['entropy']} bits")
        print(f"Estimated Crack Time: {result['crack_time']}")
        print("Feedback:")
        for fb in result['feedback']:
            print(f"- {fb}")
        print(f"Evaluation Time: {result['time_taken']} seconds")

        print("\n--- Quick Strength Check ---")
        print(f"Simple Password Strength: {simple_result}\n")

if __name__ == "__main__":
    main()
