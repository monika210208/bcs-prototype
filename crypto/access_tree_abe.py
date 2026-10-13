"""
crypto/access_tree_abe.py
-------------------------
Advanced Cryptographic Engine implementing:
1. Fine-Grained Boolean Access Tree Policy Parser (AND, OR, Threshold k-of-n, Leaf attributes)
2. Shamir's Secret Sharing Scheme & Lagrange Polynomial Interpolation over finite fields
3. Multi-Authority Attribute-Based Encryption (MA-ABE) across distinct organizational domains
4. Epoch-Based Key Ratcheting & Forward Secrecy for time-bound cryptographic access
"""

import os
import re
import json
import time
import hashlib
import hmac
from typing import List, Dict, Optional, Tuple, Set, Any

# Large 256-bit prime for finite field GF(P)
PRIME_256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F


# -----------------------------------------------------------------------------
# 1. Shamir's Secret Sharing & Finite Field Arithmetic
# -----------------------------------------------------------------------------

def mod_inv(a: int, p: int = PRIME_256) -> int:
    """Compute modular inverse using Extended Euclidean Algorithm."""
    if a < 0:
        a = (a % p + p) % p
    t, new_t = 0, 1
    r, new_r = p, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        raise ValueError("a is not invertible")
    if t < 0:
        t += p
    return t


def split_secret(secret_int: int, k: int, n: int, p: int = PRIME_256) -> List[Tuple[int, int]]:
    """
    Split secret into n shares with threshold k using a random degree (k-1) polynomial.
    f(x) = secret + a_1*x + a_2*x^2 + ... + a_{k-1}*x^{k-1} mod p
    """
    if k > n:
        raise ValueError("Threshold k cannot exceed number of shares n")
    coeffs = [secret_int] + [int.from_bytes(os.urandom(32), "big") % p for _ in range(k - 1)]
    shares = []
    for x in range(1, n + 1):
        y = 0
        x_power = 1
        for coeff in coeffs:
            y = (y + coeff * x_power) % p
            x_power = (x_power * x) % p
        shares.append((x, y))
    return shares


def reconstruct_secret(shares: List[Tuple[int, int]], p: int = PRIME_256) -> int:
    """
    Reconstruct secret f(0) using Lagrange Polynomial Interpolation from at least k shares.
    f(0) = sum_{j} (y_j * prod_{m != j} (0 - x_m) / (x_j - x_m)) mod p
    """
    secret = 0
    k = len(shares)
    for j in range(k):
        xj, yj = shares[j]
        numerator = 1
        denominator = 1
        for m in range(k):
            if m == j:
                continue
            xm, _ = shares[m]
            numerator = (numerator * (-xm)) % p
            denominator = (denominator * (xj - xm)) % p
        lagrange_basis = (numerator * mod_inv(denominator, p)) % p
        secret = (secret + yj * lagrange_basis) % p
    return secret


# -----------------------------------------------------------------------------
# 2. Boolean Access Tree Node and Evaluator
# -----------------------------------------------------------------------------

class PolicyNode:
    """Node in an access tree: LEAF, AND, OR, or THRESHOLD."""

    def __init__(self, node_type: str, value: Any = None, threshold: int = 1, children: Optional[List['PolicyNode']] = None):
        self.node_type = node_type.upper()  # 'LEAF', 'AND', 'OR', 'THRESHOLD'
        self.value = value                  # string attribute for LEAF, e.g. 'Role:Doctor'
        self.threshold = threshold          # k for THRESHOLD, len(children) for AND, 1 for OR
        self.children = children or []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.node_type,
            "value": self.value,
            "threshold": self.threshold,
            "children": [c.to_dict() for c in self.children]
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> 'PolicyNode':
        children = [cls.from_dict(c) for c in d.get("children", [])]
        return cls(
            node_type=d.get("type", "LEAF"),
            value=d.get("value"),
            threshold=d.get("threshold", 1),
            children=children
        )

    def evaluate(self, user_attributes: Set[str]) -> bool:
        """Evaluate if user attributes satisfy this policy subtree."""
        if self.node_type == "LEAF":
            return self.value in user_attributes
        if self.node_type == "AND":
            return all(c.evaluate(user_attributes) for c in self.children)
        if self.node_type == "OR":
            return any(c.evaluate(user_attributes) for c in self.children)
        if self.node_type == "THRESHOLD":
            satisfied = sum(1 for c in self.children if c.evaluate(user_attributes))
            return satisfied >= self.threshold
        return False

    def get_all_attributes(self) -> Set[str]:
        """Collect all required leaf attributes in the tree."""
        if self.node_type == "LEAF":
            return {self.value} if self.value else set()
        attrs = set()
        for child in self.children:
            attrs.update(child.get_all_attributes())
        return attrs


def parse_policy_expression(expression: str) -> PolicyNode:
    """
    Parses a human-readable boolean policy string into an Access Tree PolicyNode.
    Examples:
      - 'Role:Doctor AND Dept:Cardiology'
      - '(Role:Doctor AND Dept:Cardiology) OR Tier:Admin'
      - 'THRESHOLD(2, [Role:Doctor, Dept:Cardiology, Clearance:High])'
    """
    expr = expression.strip()
    
    # Check for THRESHOLD syntax: THRESHOLD(k, [a, b, c])
    thresh_match = re.match(r"^THRESHOLD\s*\(\s*(\d+)\s*,\s*\[(.*)\]\s*\)$", expr, re.IGNORECASE)
    if thresh_match:
        k = int(thresh_match.group(1))
        items = [x.strip() for x in thresh_match.group(2).split(",") if x.strip()]
        children = [PolicyNode("LEAF", value=item) for item in items]
        return PolicyNode("THRESHOLD", threshold=k, children=children)

    # Tokenize parentheses and boolean operators
    # If wrapped in outermost matching parentheses, strip them
    while expr.startswith("(") and expr.endswith(")"):
        # verify they match
        depth = 0
        matched = True
        for i, char in enumerate(expr[:-1]):
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    matched = False
                    break
        if matched:
            expr = expr[1:-1].strip()
        else:
            break

    # Look for top-level OR (lowest precedence)
    depth = 0
    or_indices = []
    i = 0
    tokens = []
    while i < len(expr):
        if expr[i] == "(":
            depth += 1
        elif expr[i] == ")":
            depth -= 1
        elif depth == 0:
            if expr[i:i+4].upper() == " OR ":
                or_indices.append(i)
                i += 3
        i += 1

    if or_indices:
        # Split on top-level OR
        parts = []
        last = 0
        for idx in or_indices:
            parts.append(expr[last:idx].strip())
            last = idx + 4
        parts.append(expr[last:].strip())
        children = [parse_policy_expression(p) for p in parts if p]
        return PolicyNode("OR", threshold=1, children=children)

    # Look for top-level AND
    depth = 0
    and_indices = []
    i = 0
    while i < len(expr):
        if expr[i] == "(":
            depth += 1
        elif expr[i] == ")":
            depth -= 1
        elif depth == 0:
            if expr[i:i+5].upper() == " AND ":
                and_indices.append(i)
                i += 4
        i += 1

    if and_indices:
        parts = []
        last = 0
        for idx in and_indices:
            parts.append(expr[last:idx].strip())
            last = idx + 5
        parts.append(expr[last:].strip())
        children = [parse_policy_expression(p) for p in parts if p]
        return PolicyNode("AND", threshold=len(children), children=children)

    # Base case: Leaf attribute (e.g. 'Role:Doctor')
    return PolicyNode("LEAF", value=expr)


# -----------------------------------------------------------------------------
# 3. Multi-Authority ABE (MA-ABE) & Epoch Ratcheting
# -----------------------------------------------------------------------------

class MultiAuthorityManager:
    """
    Decentralized Multi-Authority Manager where disjoint authorities
    issue attribute key tokens for specific domains:
    - 'Hospital_HR': issues 'Role:*', 'Dept:*'
    - 'Cloud_Admin': issues 'Clearance:*', 'Tier:*'
    - 'Compliance_Board': issues 'License:*', 'Audit:*'
    """

    DOMAINS = {
        "Hospital_HR": ["Role:Doctor", "Role:Nurse", "Role:Auditor", "Role:Intern", "Role:Researcher", "Dept:Cardiology", "Dept:Neurology", "Dept:Compliance", "Dept:Emergency"],
        "Cloud_Admin": ["Clearance:High", "Clearance:Restricted", "Clearance:TopSecret", "Tier:Admin", "Tier:Standard"],
        "Compliance_Board": ["License:Active", "Audit:Passed", "Jurisdiction:HIPAA"]
    }

    def __init__(self):
        self.authorities: Dict[str, bytes] = {
            domain: os.urandom(32) for domain in self.DOMAINS
        }
        self.default_authority = os.urandom(32)

    def get_authority_for_attribute(self, attr: str) -> Tuple[str, bytes]:
        for domain, attrs in self.DOMAINS.items():
            if attr in attrs or attr.startswith(domain.split("_")[0]):
                return domain, self.authorities[domain]
        return "Global_Authority", self.default_authority

    def issue_domain_attribute_token(self, user_id: str, attribute: str, epoch: int = 1) -> Dict[str, Any]:
        """Issues an epoch-bound, HMAC-signed attribute token."""
        domain, secret = self.get_authority_for_attribute(attribute)
        token_payload = f"{user_id}:{attribute}:{domain}:{epoch}"
        sig = hmac.new(secret, token_payload.encode(), hashlib.sha256).hexdigest()
        return {
            "userId": user_id,
            "attribute": attribute,
            "authorityDomain": domain,
            "epoch": epoch,
            "signature": sig
        }

    def verify_token(self, token: Dict[str, Any]) -> bool:
        domain = token.get("authorityDomain", "Global_Authority")
        secret = self.authorities.get(domain, self.default_authority)
        token_payload = f"{token['userId']}:{token['attribute']}:{domain}:{token['epoch']}"
        expected_sig = hmac.new(secret, token_payload.encode(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(token.get("signature", ""), expected_sig)


# Global multi-authority singleton
MULTI_AUTHORITY = MultiAuthorityManager()
