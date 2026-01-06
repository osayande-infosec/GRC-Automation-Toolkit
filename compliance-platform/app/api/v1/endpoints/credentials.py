"""
Credential Auditing API Endpoints
---------------------------------
NIST SP 800-63B password policy compliance checking.
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
import math
import re

from app.core.security import get_current_user, TokenData

router = APIRouter()


# Request/Response Models
class PasswordAuditRequest(BaseModel):
    """Single password audit request."""
    password: str = Field(..., min_length=1, description="Password to audit")


class BatchAuditRequest(BaseModel):
    """Batch password audit request."""
    passwords: List[str] = Field(..., description="List of passwords to audit")


class PasswordAuditResult(BaseModel):
    """Password audit result."""
    password_masked: str
    score: int = Field(..., ge=0, le=100)
    verdict: str
    entropy: float
    findings: List[str]
    nist_compliant: bool


class BatchAuditResult(BaseModel):
    """Batch audit summary."""
    total: int
    compliant: int
    non_compliant: int
    compliance_rate: float
    by_verdict: dict
    results: List[PasswordAuditResult]


# Common weak passwords
COMMON_PASSWORDS = {
    "password", "123456", "123456789", "12345678", "12345", "1234567",
    "password1", "qwerty", "abc123", "111111", "123123", "admin",
    "letmein", "welcome", "monkey", "dragon", "master", "login",
    "passw0rd", "sunshine", "princess", "football", "iloveyou",
    "password123", "admin123", "root", "toor", "pass", "test",
}


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy."""
    if not password:
        return 0.0
    char_freq = {}
    for char in password:
        char_freq[char] = char_freq.get(char, 0) + 1
    entropy = 0.0
    for freq in char_freq.values():
        prob = freq / len(password)
        entropy -= prob * math.log2(prob)
    return entropy * len(password)


def check_character_classes(password: str) -> dict:
    """Check character class diversity."""
    return {
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": bool(re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)),
    }


def assess_password(password: str) -> PasswordAuditResult:
    """Assess a single password against NIST SP 800-63B."""
    findings = []
    score = 100
    
    # Length check (NIST: minimum 8, recommend 12+)
    if len(password) < 8:
        findings.append("FAIL: Length below minimum (8 characters required)")
        score -= 40
    elif len(password) < 12:
        findings.append(f"WARN: Length OK ({len(password)} chars). Consider 12+ for better security.")
        score -= 10
    else:
        findings.append(f"PASS: Good length ({len(password)} characters)")
    
    # Character diversity
    classes = check_character_classes(password)
    class_count = sum(classes.values())
    if class_count < 2:
        findings.append("FAIL: Poor character diversity (need uppercase, lowercase, digits, special)")
        score -= 30
    elif class_count < 4:
        findings.append(f"WARN: Moderate character diversity ({class_count}/4 classes)")
        score -= 10
    else:
        findings.append("PASS: Good character diversity (4/4 classes)")
    
    # Common password check
    if password.lower() in COMMON_PASSWORDS:
        findings.append("FAIL: Password found in common password list")
        score -= 50
    
    # Entropy calculation
    entropy = calculate_entropy(password)
    if entropy < 25:
        findings.append(f"FAIL: Low entropy ({entropy:.1f} bits)")
        score -= 20
    elif entropy < 40:
        findings.append(f"WARN: Moderate entropy ({entropy:.1f} bits)")
        score -= 5
    else:
        findings.append(f"PASS: Good entropy ({entropy:.1f} bits)")
    
    # Determine verdict
    score = max(0, min(100, score))
    if score >= 90:
        verdict = "Excellent"
    elif score >= 70:
        verdict = "Strong"
    elif score >= 50:
        verdict = "Fair"
    else:
        verdict = "Weak"
    
    # NIST compliance (minimum requirements)
    nist_compliant = len(password) >= 8 and password.lower() not in COMMON_PASSWORDS
    
    # Mask password for response
    if len(password) <= 4:
        masked = "*" * len(password)
    else:
        masked = password[:2] + "*" * (len(password) - 4) + password[-2:]
    
    return PasswordAuditResult(
        password_masked=masked,
        score=score,
        verdict=verdict,
        entropy=round(entropy, 2),
        findings=findings,
        nist_compliant=nist_compliant,
    )


@router.post("/audit", response_model=PasswordAuditResult)
async def audit_password(
    request: PasswordAuditRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Audit a single password against NIST SP 800-63B guidelines.
    
    Returns:
    - Score (0-100)
    - Verdict (Weak, Fair, Strong, Excellent)
    - Entropy calculation
    - Detailed findings
    - NIST compliance status
    """
    return assess_password(request.password)


@router.post("/audit/batch", response_model=BatchAuditResult)
async def audit_passwords_batch(
    request: BatchAuditRequest,
    current_user: TokenData = Depends(get_current_user),
):
    """
    Audit multiple passwords in batch.
    
    Returns summary statistics and individual results.
    """
    if len(request.passwords) > 1000:
        raise HTTPException(
            status_code=400,
            detail="Maximum 1000 passwords per batch request"
        )
    
    results = [assess_password(pwd) for pwd in request.passwords]
    
    compliant = sum(1 for r in results if r.nist_compliant)
    by_verdict = {}
    for r in results:
        by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
    
    return BatchAuditResult(
        total=len(results),
        compliant=compliant,
        non_compliant=len(results) - compliant,
        compliance_rate=round(compliant / len(results) * 100, 1) if results else 0,
        by_verdict=by_verdict,
        results=results,
    )


@router.get("/policy")
async def get_password_policy():
    """
    Get current password policy requirements (NIST SP 800-63B).
    """
    return {
        "framework": "NIST SP 800-63B",
        "requirements": {
            "minimum_length": 8,
            "recommended_length": 12,
            "require_complexity": False,  # NIST recommends against forced complexity
            "block_common_passwords": True,
            "check_breach_databases": True,
            "allow_paste": True,
            "show_strength_meter": True,
        },
        "guidelines": [
            "Minimum 8 characters required",
            "12+ characters recommended for better security",
            "Block passwords found in breach databases",
            "Do not force arbitrary complexity rules",
            "Allow password pasting from managers",
            "Provide real-time strength feedback",
        ],
    }
