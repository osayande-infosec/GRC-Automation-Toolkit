#!/usr/bin/env python3
"""
Password Checker Module
-----------------------
GRC Automation Toolkit - Module 01

Assesses password strength based on NIST SP 800-63B guidelines:
- Minimum length requirements
- Character diversity (uppercase, lowercase, digits, special chars)
- Common password detection
- Entropy calculation

Author: osayande-infosec
License: MIT
"""

from __future__ import annotations

import argparse
import math
import re
from dataclasses import dataclass, field
from typing import List


# Common weak passwords to check against
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "password1", "qwerty", "abc123", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "master", "login",
    "passw0rd", "sunshine", "princess", "football", "iloveyou",
    "password123", "admin123", "root", "toor", "pass", "test",
}


@dataclass
class PasswordResult:
    """Result of password assessment."""
    password: str
    score: int  # 0-100
    verdict: str  # Weak, Fair, Good, Strong, Excellent
    findings: List[str] = field(default_factory=list)
    entropy: float = 0.0


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of the password."""
    if not password:
        return 0.0
    
    # Count character frequencies
    freq = {}
    for char in password:
        freq[char] = freq.get(char, 0) + 1
    
    # Calculate entropy
    entropy = 0.0
    length = len(password)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    
    # Scale by length for bits of entropy
    return entropy * length


def check_character_classes(password: str) -> dict:
    """Check which character classes are present."""
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digits": bool(re.search(r"\d", password)),
        "special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=\[\]\\;'/`~]", password)),
    }


def assess_password(password: str) -> PasswordResult:
    """
    Assess password strength and return detailed results.
    
    Args:
        password: The password string to assess
        
    Returns:
        PasswordResult with score, verdict, and findings
    """
    findings = []
    score = 0
    
    # Length checks (NIST recommends minimum 8, prefers 15+)
    length = len(password)
    if length < 8:
        findings.append(f"Too short ({length} chars). Minimum 8 required.")
    elif length < 12:
        findings.append(f"Length OK ({length} chars). Consider 12+ for better security.")
        score += 15
    elif length < 15:
        findings.append(f"Good length ({length} chars).")
        score += 25
    else:
        findings.append(f"Excellent length ({length} chars).")
        score += 35
    
    # Character class checks
    classes = check_character_classes(password)
    class_count = sum(classes.values())
    
    if not classes["lowercase"]:
        findings.append("Missing lowercase letters.")
    else:
        score += 10
        
    if not classes["uppercase"]:
        findings.append("Missing uppercase letters.")
    else:
        score += 10
        
    if not classes["digits"]:
        findings.append("Missing digits.")
    else:
        score += 10
        
    if not classes["special"]:
        findings.append("Missing special characters.")
    else:
        score += 15
    
    # Bonus for character diversity
    if class_count >= 3:
        score += 10
        findings.append(f"Good character diversity ({class_count}/4 classes).")
    elif class_count == 4:
        score += 15
        findings.append("Excellent character diversity (all 4 classes).")
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        findings.append("WARNING: This is a commonly used password!")
        score = max(0, score - 50)
    
    # Repeated characters check
    if re.search(r"(.)\1{2,}", password):
        findings.append("Contains repeated characters (e.g., 'aaa').")
        score = max(0, score - 10)
    
    # Sequential patterns check
    if re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|def)", password.lower()):
        findings.append("Contains sequential patterns.")
        score = max(0, score - 10)
    
    # Calculate entropy
    entropy = calculate_entropy(password)
    if entropy > 50:
        findings.append(f"High entropy ({entropy:.1f} bits).")
        score += 5
    elif entropy > 30:
        findings.append(f"Moderate entropy ({entropy:.1f} bits).")
    else:
        findings.append(f"Low entropy ({entropy:.1f} bits).")
    
    # Determine verdict
    score = min(100, max(0, score))
    if score >= 80:
        verdict = "Excellent"
    elif score >= 60:
        verdict = "Strong"
    elif score >= 40:
        verdict = "Good"
    elif score >= 20:
        verdict = "Fair"
    else:
        verdict = "Weak"
    
    return PasswordResult(
        password=password,
        score=score,
        verdict=verdict,
        findings=findings,
        entropy=entropy
    )


def main() -> None:
    """CLI entry point for password checker."""
    parser = argparse.ArgumentParser(
        description="Assess password strength based on NIST guidelines.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_checker.py --password MySecureP@ss123
  python password_checker.py -p "Complex!Password#2024"
        """
    )
    parser.add_argument(
        "--password", "-p",
        required=True,
        help="Password to assess"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed findings"
    )
    
    args = parser.parse_args()
    result = assess_password(args.password)
    
    print(f"\n{'='*50}")
    print(f"Password Assessment Results")
    print(f"{'='*50}")
    print(f"Score:    {result.score}/100")
    print(f"Verdict:  {result.verdict}")
    print(f"Entropy:  {result.entropy:.2f} bits")
    
    if args.verbose or result.verdict in ("Weak", "Fair"):
        print(f"\nFindings:")
        for finding in result.findings:
            print(f"  • {finding}")
    
    print(f"{'='*50}\n")


if __name__ == "__main__":
    main()
