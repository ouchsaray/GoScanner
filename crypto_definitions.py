# Definitions of cryptographic packages, functions, and libraries for Go

# Security severity levels
SEVERITY = {
    "HIGH": "HIGH",
    "MEDIUM": "MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO"
}

# Common Go standard crypto packages with security ratings and information
CRYPTO_PACKAGES = [
    {"name": "crypto", "severity": SEVERITY["INFO"], "description": "Core cryptography package"},
    {"name": "crypto/aes", "severity": SEVERITY["INFO"], "description": "AES block cipher implementation"},
    {"name": "crypto/cipher", "severity": SEVERITY["INFO"], "description": "Cryptographic cipher interfaces"},
    {"name": "crypto/des", "severity": SEVERITY["HIGH"], "description": "DES and Triple DES ciphers - Insecure legacy algorithm", 
     "recommendation": "Use AES instead of DES/3DES as DES uses small key sizes vulnerable to brute force attacks"},
    {"name": "crypto/dsa", "severity": SEVERITY["MEDIUM"], "description": "Digital Signature Algorithm - Consider using ECDSA for newer applications", 
     "recommendation": "Consider using ECDSA or Ed25519 for digital signatures"},
    {"name": "crypto/ecdsa", "severity": SEVERITY["INFO"], "description": "Elliptic Curve Digital Signature Algorithm"},
    {"name": "crypto/ed25519", "severity": SEVERITY["INFO"], "description": "Ed25519 signature algorithm"},
    {"name": "crypto/elliptic", "severity": SEVERITY["INFO"], "description": "Elliptic curve cryptography implementation"},
    {"name": "crypto/hmac", "severity": SEVERITY["INFO"], "description": "HMAC (Hash-based Message Authentication Code)"},
    {"name": "crypto/md5", "severity": SEVERITY["HIGH"], "description": "MD5 hash algorithm - Cryptographically broken",
     "recommendation": "Replace with SHA-256 or SHA-3, MD5 is vulnerable to collision attacks"},
    {"name": "crypto/rand", "severity": SEVERITY["INFO"], "description": "Cryptographically secure random number generator"},
    {"name": "crypto/rc4", "severity": SEVERITY["HIGH"], "description": "RC4 stream cipher - Known to be insecure",
     "recommendation": "Replace with AES-GCM or ChaCha20-Poly1305, RC4 has serious weaknesses"},
    {"name": "crypto/rsa", "severity": SEVERITY["INFO"], "description": "RSA encryption and signing"},
    {"name": "crypto/sha1", "severity": SEVERITY["HIGH"], "description": "SHA-1 hash algorithm - No longer secure for signatures",
     "recommendation": "Replace with SHA-256 or SHA-3 as SHA-1 is vulnerable to collision attacks"},
    {"name": "crypto/sha256", "severity": SEVERITY["INFO"], "description": "SHA-224 and SHA-256 hash algorithms"},
    {"name": "crypto/sha512", "severity": SEVERITY["INFO"], "description": "SHA-384 and SHA-512 hash algorithms"},
    {"name": "crypto/subtle", "severity": SEVERITY["INFO"], "description": "Constant-time comparison functions to prevent timing attacks"},
    {"name": "crypto/tls", "severity": SEVERITY["INFO"], "description": "Transport Layer Security (TLS) protocol"},
    {"name": "crypto/x509", "severity": SEVERITY["INFO"], "description": "X.509 certificate handling"},
    {"name": "encoding/base32", "severity": SEVERITY["INFO"], "description": "Base32 encoding"},
    {"name": "encoding/base64", "severity": SEVERITY["INFO"], "description": "Base64 encoding"},
    {"name": "encoding/hex", "severity": SEVERITY["INFO"], "description": "Hexadecimal encoding"},
    {"name": "hash", "severity": SEVERITY["INFO"], "description": "Hash function interfaces"},
    {"name": "hash/adler32", "severity": SEVERITY["MEDIUM"], "description": "Adler-32 checksum - Not suitable for cryptographic use",
     "recommendation": "Use cryptographic hashes from crypto/sha256 for security purposes"},
    {"name": "hash/crc32", "severity": SEVERITY["MEDIUM"], "description": "CRC-32 checksum - Not suitable for cryptographic use",
     "recommendation": "Use cryptographic hashes from crypto/sha256 for security purposes"},
    {"name": "hash/crc64", "severity": SEVERITY["MEDIUM"], "description": "CRC-64 checksum - Not suitable for cryptographic use",
     "recommendation": "Use cryptographic hashes from crypto/sha256 for security purposes"},
    {"name": "hash/fnv", "severity": SEVERITY["MEDIUM"], "description": "FNV hash functions - Not suitable for cryptographic use",
     "recommendation": "Use cryptographic hashes from crypto/sha256 for security purposes"},
    {"name": "hash/maphash", "severity": SEVERITY["INFO"], "description": "Hash function for internal use"}
]

# Third-party crypto libraries and their import patterns with security information
CRYPTO_LIBRARIES = {
    "golang.org/x/crypto": {
        "pattern": r'golang\.org/x/crypto',
        "severity": SEVERITY["INFO"],
        "description": "Extended cryptographic libraries for Go",
        "recommendation": "Regularly update to the latest version for security patches"
    },
    "golang.org/x/crypto/ssh": {
        "pattern": r'golang\.org/x/crypto/ssh',
        "severity": SEVERITY["MEDIUM"],
        "description": "SSH client and server implementations",
        "recommendation": "Verify proper key management and authentication methods"
    },
    "golang.org/x/crypto/bcrypt": {
        "pattern": r'golang\.org/x/crypto/bcrypt',
        "severity": SEVERITY["INFO"],
        "description": "Password hashing function",
        "recommendation": "Use sufficient cost parameters (>= 12) for security"
    },
    "github.com/tjfoc/gmsm": {
        "pattern": r'github\.com/tjfoc/gmsm',
        "severity": SEVERITY["INFO"],
        "description": "Chinese national cryptographic standards implementation",
        "recommendation": "Ensure this meets your regulatory requirements"
    },
    "github.com/ethereum/go-ethereum/crypto": {
        "pattern": r'github\.com/ethereum/go-ethereum/crypto',
        "severity": SEVERITY["INFO"],
        "description": "Ethereum cryptographic primitives",
        "recommendation": "Keep updated with latest security patches"
    },
    "github.com/secure-io/sio-go": {
        "pattern": r'github\.com/secure-io/sio-go',
        "severity": SEVERITY["INFO"],
        "description": "Secure encrypted I/O operations",
        "recommendation": "Follow recommended usage patterns in documentation"
    },
    "github.com/square/go-jose": {
        "pattern": r'github\.com/square/go-jose',
        "severity": SEVERITY["INFO"],
        "description": "JSON Object Signing and Encryption (JOSE) implementation",
        "recommendation": "Use recommended key sizes and algorithms"
    },
    # Additional libraries
    "github.com/gtank/cryptopasta": {
        "pattern": r'github\.com/gtank/cryptopasta',
        "severity": SEVERITY["INFO"],
        "description": "Copy-pastable cryptographic code with sensible defaults",
        "recommendation": "Useful for common crypto tasks but verify it's up to date"
    },
    "github.com/pion/dtls": {
        "pattern": r'github\.com/pion/dtls',
        "severity": SEVERITY["MEDIUM"],
        "description": "DTLS (Datagram Transport Layer Security) implementation",
        "recommendation": "Verify proper certificate validation and cipher selection"
    },
    "github.com/minio/sio": {
        "pattern": r'github\.com/minio/sio',
        "severity": SEVERITY["INFO"],
        "description": "Encrypted I/O streaming library (especially for S3)",
        "recommendation": "Follow documentation for proper key management"
    }
}

# Common cryptographic functions with security ratings and recommendations
CRYPTO_FUNCTIONS = [
    {"name": "Encrypt", "severity": SEVERITY["INFO"], "description": "Generic encryption function"},
    {"name": "Decrypt", "severity": SEVERITY["INFO"], "description": "Generic decryption function"},
    {"name": "Hash", "severity": SEVERITY["INFO"], "description": "Generic hashing function"},
    {"name": "Sign", "severity": SEVERITY["INFO"], "description": "Digital signature creation"},
    {"name": "Verify", "severity": SEVERITY["INFO"], "description": "Digital signature verification"},
    {"name": "GenerateKey", "severity": SEVERITY["INFO"], "description": "Cryptographic key generation"},
    {"name": "NewCipher", "severity": SEVERITY["INFO"], "description": "Create new cipher instance"},
    {"name": "NewGCM", "severity": SEVERITY["INFO"], "description": "Galois/Counter Mode authenticated encryption",
     "recommendation": "Ensure unique nonces are used for each encryption operation"},
    {"name": "NewCBCDecrypter", "severity": SEVERITY["MEDIUM"], "description": "CBC mode decryption",
     "recommendation": "Ensure proper padding validation to prevent padding oracle attacks"},
    {"name": "NewCBCEncrypter", "severity": SEVERITY["MEDIUM"], "description": "CBC mode encryption",
     "recommendation": "Use authenticated encryption modes like GCM instead when possible"},
    {"name": "NewCTR", "severity": SEVERITY["MEDIUM"], "description": "CTR mode encryption/decryption",
     "recommendation": "Ensure unique nonce/IV combinations and add separate authentication"},
    {"name": "NewOFB", "severity": SEVERITY["MEDIUM"], "description": "OFB mode encryption/decryption",
     "recommendation": "Consider authenticated encryption modes like GCM instead"},
    {"name": "NewCFB", "severity": SEVERITY["MEDIUM"], "description": "CFB mode encryption/decryption",
     "recommendation": "Consider authenticated encryption modes like GCM instead"},
    {"name": "GenerateRandom", "severity": SEVERITY["INFO"], "description": "Generate random bytes",
     "recommendation": "Use crypto/rand for cryptographic operations, not math/rand"},
    {"name": "RandomBytes", "severity": SEVERITY["INFO"], "description": "Generate random bytes",
     "recommendation": "Use crypto/rand for cryptographic operations, not math/rand"},
    {"name": "GenerateIV", "severity": SEVERITY["INFO"], "description": "Generate initialization vector",
     "recommendation": "Ensure IVs are of sufficient length and are never reused"},
    {"name": "GenerateNonce", "severity": SEVERITY["INFO"], "description": "Generate nonce value",
     "recommendation": "Ensure nonces are of sufficient length and are never reused"},
    {"name": "PBKDF2", "severity": SEVERITY["MEDIUM"], "description": "Password-Based Key Derivation Function 2",
     "recommendation": "Use sufficiently high iteration count (>= 100,000) and consider Argon2 instead"},
    {"name": "Scrypt", "severity": SEVERITY["INFO"], "description": "Scrypt key derivation function",
     "recommendation": "Ensure proper parameter selection for memory and CPU cost"},
    {"name": "Argon2", "severity": SEVERITY["INFO"], "description": "Argon2 key derivation function",
     "recommendation": "Recommended KDF for password hashing with proper parameters"}
]

# Common cryptographic constants with security assessments
CRYPTO_CONSTANTS = {
    "AES Modes": {
        "pattern": r'CBC|CFB|CTR|GCM|OFB',
        "severity": SEVERITY["INFO"],
        "description": "AES block cipher modes of operation",
        "recommendation": "GCM is generally preferred for providing authentication with encryption"
    },
    "RSA Padding": {
        "pattern": r'PKCS1|OAEP|PSS',
        "severity": SEVERITY["INFO"],
        "description": "RSA padding schemes",
        "recommendation": "OAEP is preferred for encryption, PSS for signatures"
    },
    "Insecure Hash Algorithms": {
        "pattern": r'MD5|SHA1',
        "severity": SEVERITY["HIGH"],
        "description": "Cryptographically broken hash algorithms",
        "recommendation": "Replace with SHA-256, SHA-3, or BLAKE2"
    },
    "Secure Hash Algorithms": {
        "pattern": r'SHA224|SHA256|SHA384|SHA512|SHA3',
        "severity": SEVERITY["INFO"],
        "description": "Secure hash algorithms",
        "recommendation": "SHA-256 or higher is recommended for most applications"
    },
    "Small Key Sizes": {
        "pattern": r'(Key|key)(Size|Bits|Length)[=:]\s*(512|1024|128|40|56|64)\b',
        "severity": SEVERITY["HIGH"],
        "description": "Small key sizes that may be vulnerable to attacks",
        "recommendation": "Use at least 2048 bits for RSA/DSA keys, 256 bits for ECC, and 128 bits for symmetric keys"
    },
    "Hardcoded Crypto Values": {
        "pattern": r'(key|iv|salt|password|secret)\s*[:=]\s*["\'`][^"\'`]+["\'`]',
        "severity": SEVERITY["HIGH"],
        "description": "Potentially hardcoded cryptographic values",
        "recommendation": "Never hardcode sensitive values, use proper key management"
    },
    "Custom Crypto Implementation": {
        "pattern": r'func\s+(\w+)(Encrypt|Decrypt|Hash|Cipher|Crypt)',
        "severity": SEVERITY["MEDIUM"],
        "description": "Potentially custom cryptographic implementation",
        "recommendation": "Use standard, well-vetted libraries instead of custom implementations"
    },
    "Insecure Random": {
        "pattern": r'(math/rand|rand\.Intn|rand\.Int|rand\.Float)',
        "severity": SEVERITY["HIGH"],
        "description": "Non-cryptographic random number generator",
        "recommendation": "Use crypto/rand for security-sensitive operations"
    }
}

# Potential insecure practices to detect
CRYPTO_ANTIPATTERNS = {
    "PEM Private Key": {
        "pattern": r'-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----',
        "severity": SEVERITY["HIGH"],
        "description": "PEM-encoded private key may be hardcoded",
        "recommendation": "Store keys securely, not in source code"
    },
    "Static IV": {
        "pattern": r'iv\s*:?=\s*\[\]byte{[^}]+}',
        "severity": SEVERITY["HIGH"], 
        "description": "Static initialization vector",
        "recommendation": "Generate a unique IV for each encryption operation"
    },
    "Weak Password Validation": {
        "pattern": r'(password|passwd)\s*==\s*["\'][^"\']+["\']',
        "severity": SEVERITY["HIGH"],
        "description": "Direct string comparison for passwords",
        "recommendation": "Use constant-time comparison functions to prevent timing attacks"
    },
    "Short Iterations": {
        "pattern": r'(iterations|iter|rounds)\s*:?=\s*(1000|[1-9][0-9][0-9]|[1-9][0-9]|[0-9])\b',
        "severity": SEVERITY["MEDIUM"],
        "description": "Low iteration count for key derivation functions",
        "recommendation": "Use at least 100,000 iterations for PBKDF2 or appropriate parameters for other KDFs"
    },
    "Insecure TLS Configuration": {
        "pattern": r'InsecureSkipVerify\s*:?\s*true',
        "severity": SEVERITY["HIGH"],
        "description": "TLS certificate verification is disabled",
        "recommendation": "Always verify TLS certificates in production code"
    }
}
