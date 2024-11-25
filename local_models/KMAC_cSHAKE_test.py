from keccak_local import CSHAKE_imp

def process_hex_message(hex_message):
    # Convert the hex message to bytes
    message_bytes = hex_message.to_bytes(16, byteorder="big")  # 128-bit = 16 bytes

    # Split into 64-bit chunks
    chunks = [message_bytes[i:i+8] for i in range(0, len(message_bytes), 8)]

    # Reverse the byte order of each chunk
    reversed_chunks = [chunk[::-1] for chunk in chunks]

    # Reconstruct the final byte sequence
    result_bytes = b"".join(reversed_chunks)

    # Convert back to a hexadecimal integer
    result_hex = int.from_bytes(result_bytes, byteorder="big")

    return result_hex



# Example input message as a hexadecimal integer
hex_message = 0x4E6C2EA4A75D0E39A9CD0A446D6547F5

# Call the CSHAKE_imp function
CSHAKE_imp(hex_message)
hex_message = 0x847430d215074cfc053a738d6959640e
CSHAKE_imp(hex_message)

hex_message = process_hex_message(0x5440943c2d636dfcc32dc6317d33394a)
# print(hex(hex_message))
CSHAKE_imp(hex_message)
