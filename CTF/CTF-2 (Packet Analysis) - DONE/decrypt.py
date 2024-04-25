def CaesarCipher(text: str, shift: int, encrypt: bool) -> str: 
    result = ""
    for i in range(len(text)):
        char = text[i].lower()
        if char == " ": 
            result += " "
        else:
            if encrypt:
                result += chr(((ord(char) + shift - 97) % 26) + 97) 
            else:
                if ord(char) >= ord('a') and ord(char) <= ord('z'):
                    result += chr(((ord(char) - shift - 97) % 26) + 97)
                else :
                    result += char
    return result

print(CaesarCipher("Gur synt vf cvpbPGS{c33xno00_1_f33_h_qrnqorrs}", 13, False).upper())

