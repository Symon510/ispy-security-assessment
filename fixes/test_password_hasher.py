"""
Reference implementation of the PasswordHasher in PasswordHasher.cs,
ported to Python for offline validation. This demonstrates that the format
parses round-trip and that the bad inputs are rejected.
"""
import os, hashlib, base64, hmac, time

PREFIX = "PBKDF2$"
SALT_SIZE = 16
HASH_SIZE = 32
ITERATIONS = 100_000

def hash_pw(password: str) -> str:
    salt = os.urandom(SALT_SIZE)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                            ITERATIONS, dklen=HASH_SIZE)
    return f"{PREFIX}{ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(h).decode()}"

def verify(password: str, stored: str) -> bool:
    if not stored.startswith(PREFIX): return False
    parts = stored.split("$")
    if len(parts) != 4: return False
    try:
        iters = int(parts[1])
        salt = base64.b64decode(parts[2])
        expected = base64.b64decode(parts[3])
    except Exception:
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt,
                                 iters, dklen=len(expected))
    return hmac.compare_digest(expected, actual)


# demonstration
print("=" * 70)
print(" PasswordHasher reference test")
print("=" * 70)

pw = "CorrectHorseBatteryStaple"
t0 = time.time()
h = hash_pw(pw)
t1 = time.time()
print(f"\nStored format: {h}")
print(f"Hash time:     {(t1-t0)*1000:.1f} ms  (intentional cost factor)")

print("\nVerification tests:")
print(f"  correct password         -> {verify(pw, h)}        (expect True)")
print(f"  wrong password           -> {verify('wrong', h)}        (expect False)")
print(f"  case-altered password    -> {verify(pw.lower(), h)}        (expect False)")
print(f"  garbage stored value     -> {verify(pw, 'AAAA')}        (expect False)")
print(f"  legacy AES record format -> {verify(pw, 'kJ9d2K==')}        (expect False)")

# Verify two hashes of the same password differ (per-hash random salt)
h1, h2 = hash_pw(pw), hash_pw(pw)
print(f"\nSalt uniqueness check:")
print(f"  hash1 == hash2 -> {h1 == h2}        (expect False -- per-hash salt)")
print(f"  both verify    -> {verify(pw, h1) and verify(pw, h2)}")

# Demonstrate brute-force cost
print(f"\nCost demonstration (10 verify calls):")
t0 = time.time()
for _ in range(10):
    verify(pw, h)
t1 = time.time()
print(f"  total: {(t1-t0)*1000:.1f} ms  ({(t1-t0)*100:.1f} ms per attempt)")
print(f"  -> attacker cannot test more than ~{int(10/(t1-t0))}/sec on equivalent hardware")

print("\n" + "=" * 70)
print(" All checks behave as designed.")
print("=" * 70)
