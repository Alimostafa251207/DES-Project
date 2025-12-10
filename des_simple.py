"""
SIMPLE DES IMPLEMENTATION - COMPLETE FOR BEGINNERS
Just copy and paste this entire file.
"""

# ============================================================================
# PART 1: ALL THE TABLES DES NEEDS (DON'T CHANGE THESE)
# ============================================================================

# These are like "rules" for how to shuffle bits around
# (You don't need to understand these completely, just know they're needed)

# Initial shuffle (IP)
IP = [57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7,
      56, 48, 40, 32, 24, 16, 8, 0,
      58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6]

# Final shuffle (FP) - opposite of IP
FP = [39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25,
      32, 0, 40, 8, 48, 16, 56, 24]

# Expansion box - makes 32 bits into 48 bits
E = [31, 0, 1, 2, 3, 4,
     3, 4, 5, 6, 7, 8,
     7, 8, 9, 10, 11, 12,
     11, 12, 13, 14, 15, 16,
     15, 16, 17, 18, 19, 20,
     19, 20, 21, 22, 23, 24,
     23, 24, 25, 26, 27, 28,
     27, 28, 29, 30, 31, 0]

# P-box - shuffles 32 bits
P = [15, 6, 19, 20, 28, 11, 27, 16,
     0, 14, 22, 25, 4, 17, 30, 9,
     1, 7, 23, 13, 31, 26, 2, 8,
     18, 12, 29, 5, 21, 10, 3, 24]

# S-boxes - These are SECRET TABLES that do the main encryption
# Think of them as magic number converters
S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
    
    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
    
    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
    
    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
    
    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
    
    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
    
    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Key tables - how to make round keys from main key
PC1 = [56, 48, 40, 32, 24, 16, 8,
       0, 57, 49, 41, 33, 25, 17,
       9, 1, 58, 50, 42, 34, 26,
       18, 10, 2, 59, 51, 43, 35,
       62, 54, 46, 38, 30, 22, 14,
       6, 61, 53, 45, 37, 29, 21,
       13, 5, 60, 52, 44, 36, 28,
       20, 12, 4, 27, 19, 11, 3]

PC2 = [13, 16, 10, 23, 0, 4,
       2, 27, 14, 5, 20, 9,
       22, 18, 11, 3, 25, 7,
       15, 6, 26, 19, 12, 1,
       40, 51, 30, 36, 46, 54,
       29, 39, 50, 44, 32, 47,
       43, 48, 38, 55, 33, 52,
       45, 41, 49, 35, 28, 31]

# How many times to shift key parts each round
KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# ============================================================================
# PART 2: HELPER FUNCTIONS (TOOLS WE NEED)
# ============================================================================

def hex_to_bin(hex_str, length=64):
    """Convert hex (like 'A1') to binary (like '10100001')"""
    # Remove spaces if any
    hex_str = hex_str.strip().replace(' ', '').replace('\n', '')
    
    # Convert to binary and pad with zeros
    binary = bin(int(hex_str, 16))[2:]  # [2:] removes '0b' prefix
    return binary.zfill(length)  # Add zeros to make correct length

def bin_to_hex(bin_str):
    """Convert binary back to hex"""
    # Remove spaces
    bin_str = bin_str.replace(' ', '')
    
    # Convert to hex
    hex_str = hex(int(bin_str, 2))[2:]  # [2:] removes '0x' prefix
    
    # Make it uppercase and pad if needed
    return hex_str.upper().zfill(16)

def permute(bits, table):
    """Shuffle bits according to a table"""
    # Example: table = [2, 0, 1], bits = "ABC" → returns "CAB"
    result = []
    for position in table:
        result.append(bits[position])
    return ''.join(result)

def left_shift(bits, n):
    """Shift bits left, wrap around"""
    # Example: "ABCD" shifted 1 → "BCDA"
    return bits[n:] + bits[:n]

def xor(bits1, bits2):
    """XOR two strings of bits"""
    # XOR: 0⊕0=0, 0⊕1=1, 1⊕0=1, 1⊕1=0
    result = []
    for b1, b2 in zip(bits1, bits2):
        result.append('1' if b1 != b2 else '0')
    return ''.join(result)

# ============================================================================
# PART 3: MAIN DES CLASS - THE ACTUAL ENCRYPTION
# ============================================================================

class SimpleDES:
    """A simple DES implementation for learning"""
    
    def __init__(self, key_hex):
        """Initialize with a key"""
        # Store the key
        self.key = key_hex
        # Convert key to binary
        self.key_bits = hex_to_bin(key_hex, 64)
        # Generate the 16 round keys
        self.round_keys = self._generate_round_keys()
    
    def _generate_round_keys(self):
        """Make 16 smaller keys from the main key"""
        # Step 1: Apply first permutation (PC1)
        key_bits = permute(self.key_bits, PC1)
        
        # Step 2: Split into left and right halves
        left = key_bits[:28]  # First 28 bits
        right = key_bits[28:]  # Last 28 bits
        
        round_keys = []
        
        # Step 3: For each of 16 rounds
        for i in range(16):
            # Shift both halves
            shift_amount = KEY_SHIFTS[i]
            left = left_shift(left, shift_amount)
            right = left_shift(right, shift_amount)
            
            # Combine and apply second permutation (PC2)
            combined = left + right
            round_key = permute(combined, PC2)
            round_keys.append(round_key)
        
        return round_keys
    
    def _s_box_substitution(self, bits):
        """The magic S-box transformation"""
        if len(bits) != 48:
            return "ERROR: Need 48 bits"
        
        result = []
        
        # Process 8 groups of 6 bits each
        for box_num in range(8):
            # Take 6 bits
            group = bits[box_num*6:(box_num+1)*6]
            
            # First and last bit determine row (0-3)
            row = int(group[0] + group[5], 2)
            
            # Middle 4 bits determine column (0-15)
            col = int(group[1:5], 2)
            
            # Look up value in S-box
            value = S_BOXES[box_num][row][col]
            
            # Convert to 4-bit binary
            result.append(bin(value)[2:].zfill(4))
        
        return ''.join(result)
    
    def _round_function(self, right_half, round_key):
        """One round of DES encryption"""
        # Step 1: Expand 32 bits to 48 bits
        expanded = permute(right_half, E)
        
        # Step 2: XOR with round key
        xored = xor(expanded, round_key)
        
        # Step 3: S-box substitution (48 → 32 bits)
        substituted = self._s_box_substitution(xored)
        
        # Step 4: P-box permutation
        permuted = permute(substituted, P)
        
        return permuted
    
    def encrypt_block(self, plaintext_hex):
        """Encrypt one 64-bit block"""
        # Step 1: Convert plaintext to binary
        plaintext_bits = hex_to_bin(plaintext_hex, 64)
        
        # Step 2: Initial permutation
        bits = permute(plaintext_bits, IP)
        
        # Step 3: Split into left and right halves
        left = bits[:32]
        right = bits[32:]
        
        # Step 4: 16 rounds of encryption
        for i in range(16):
            # Save old left
            old_left = left
            
            # New left = old right
            left = right
            
            # New right = old left XOR f(old right, round key)
            f_result = self._round_function(right, self.round_keys[i])
            right = xor(old_left, f_result)
        
        # Step 5: Final swap and permutation
        combined = right + left  # Note: swapped!
        ciphertext_bits = permute(combined, FP)
        
        # Step 6: Convert back to hex
        return bin_to_hex(ciphertext_bits)
    
    def decrypt_block(self, ciphertext_hex):
        """Decrypt one 64-bit block"""
        # Decryption is same as encryption but with reversed keys!
        
        # Step 1: Convert to binary
        ciphertext_bits = hex_to_bin(ciphertext_hex, 64)
        
        # Step 2: Initial permutation
        bits = permute(ciphertext_bits, IP)
        
        # Step 3: Split
        left = bits[:32]
        right = bits[32:]
        
        # Step 4: 16 rounds with REVERSED keys
        for i in range(15, -1, -1):  # Count backward: 15, 14, ..., 0
            old_right = right
            right = left
            f_result = self._round_function(left, self.round_keys[i])
            left = xor(old_right, f_result)
        
        # Step 5: Final swap and permutation
        combined = right + left  # Note: swapped!
        plaintext_bits = permute(combined, FP)
        
        # Step 6: Convert back to hex
        return bin_to_hex(plaintext_bits)

# ============================================================================
# PART 4: TESTING - SEE IF IT WORKS
# ============================================================================

def main():
    """Test our DES implementation"""
    print("="*60)
    print("DES ALGORITHM - SIMPLE VERSION")
    print("="*60)
    print()
    
    # KNOWN TEST: If this works, our code is correct!
    print("1. KNOWN TEST (from NIST standards):")
    print("-"*40)
    
    # Test data that MUST produce known result
    key = "133457799BBCDFF1"
    plaintext = "0123456789ABCDEF"
    expected_ciphertext = "85E813540F0AB405"
    
    print(f"Key:        {key}")
    print(f"Plaintext:  {plaintext}")
    
    # Create DES object
    des = SimpleDES(key)
    
    # Encrypt
    ciphertext = des.encrypt_block(plaintext)
    print(f"Ciphertext: {ciphertext}")
    print(f"Expected:   {expected_ciphertext}")
    
    # Decrypt
    decrypted = des.decrypt_block(ciphertext)
    print(f"Decrypted:  {decrypted}")
    
    # Check results
    if ciphertext == expected_ciphertext:
        print("✓ ENCRYPTION CORRECT!")
    else:
        print("✗ ENCRYPTION WRONG!")
    
    if decrypted == plaintext:
        print("✓ DECRYPTION CORRECT!")
    else:
        print("✗ DECRYPTION WRONG!")
    
    print()
    
    # YOUR OWN TEST
    print("2. YOUR OWN TEST:")
    print("-"*40)
    
    # Try your own data
    your_key = "0E329232EA6D0D73"
    your_data = "8787878787878787"
    
    print(f"Your key:   {your_key}")
    print(f"Your data:  {your_data}")
    
    des2 = SimpleDES(your_key)
    encrypted = des2.encrypt_block(your_data)
    decrypted = des2.decrypt_block(encrypted)
    
    print(f"Encrypted:  {encrypted}")
    print(f"Decrypted:  {decrypted}")
    
    if your_data == decrypted:
        print("✓ YOUR TEST PASSED!")
    else:
        print("✗ YOUR TEST FAILED!")
    
    print()
    
    # SHOW WHAT'S HAPPENING
    print("3. WHAT JUST HAPPENED:")
    print("-"*40)
    print("1. We took a 64-bit plaintext (16 hex digits)")
    print("2. We used a 64-bit key (16 hex digits)")
    print("3. DES did 16 rounds of scrambling")
    print("4. Each round used a different 48-bit subkey")
    print("5. Final result is encrypted ciphertext")
    print("6. Decryption reversed the process")
    print()
    print("Key size: 64 bits (56 real bits + 8 parity bits)")
    print("Block size: 64 bits")
    print("Rounds: 16")
    
    print()
    print("="*60)
    print("IMPORTANT: DES is BROKEN! Don't use for real security.")
    print("This is for LEARNING ONLY.")
    print("="*60)

# Run the test
if __name__ == "__main__":
    main()