#Implementação do S-DES (Simplified DES)
#Chave: 1010000010
#Bloco de dados: 11010111

def permute(input_bits, permutation_table, perm_type):
    """
    Realiza a permutação específica dos bits de acordo com o tipo de permutação.
    Args:
        input_bits: String de bits para permutar
        permutation_table: Tabela com as posições da permutação
        perm_type: Tipo de permutação ('P10', 'P8', 'IP', 'IP-1', 'EP', 'P4')
    """
    output = list(input_bits)  #lista para facilitar a troca
    result = ""
    
    #ermutação para gerar a chave de 10 bits
    if perm_type == 'P10': 
        #P10: [3,5,2,7,4,10,1,9,8,6]
        result = input_bits[2] + input_bits[4] + input_bits[1] + input_bits[6] + \
                input_bits[3] + input_bits[9] + input_bits[0] + input_bits[8] + \
                input_bits[7] + input_bits[5]
        print('P10:', result)
        
    #permutação para gerar as subchaves de 8 bits
    elif perm_type == 'P8':  
        #P8:[6,3,7,4,8,5,10,9]
        result = input_bits[5] + input_bits[2] + input_bits[6] + input_bits[3] + \
                input_bits[7] + input_bits[4] + input_bits[9] + input_bits[8]
        print('P8:', result)

    #permutação inicial do bloco de dados (plaintext)  
    elif perm_type == 'IP':  
        #IP: [2,6,3,1,4,8,5,7]
        result = input_bits[1] + input_bits[5] + input_bits[2] + input_bits[0] + \
                input_bits[3] + input_bits[7] + input_bits[4] + input_bits[6]
        print('\nIP:', result)
        
    #permutação final do bloco de dados (ciphertext)
    elif perm_type == 'IP-1':  
        #IP-1: [4,1,3,5,7,2,8,6]
        result = input_bits[3] + input_bits[0] + input_bits[2] + input_bits[4] + \
                input_bits[6] + input_bits[1] + input_bits[7] + input_bits[5]
        print('IP-1:', result)

    #Expansão/Permutação na função fK    
    elif perm_type == 'EP':  
        #EP: [4,1,2,3,2,3,4,1]
        result = input_bits[3] + input_bits[0] + input_bits[1] + input_bits[2] + \
                input_bits[1] + input_bits[2] + input_bits[3] + input_bits[0]
        print('EP:', result)

    #Permutação na função fK após as S-boxes  
    elif perm_type == 'P4':  
        #P4: [2,4,3,1]
        result = input_bits[1] + input_bits[3] + input_bits[2] + input_bits[0]
        print('P4:', result)
    
    else:
        print(f"Tipo de permutação desconhecido: {perm_type}")
    
    return result

def left_shift(bits, positions):
    """
    Realiza o deslocamento circular à esquerda dos bits
    """
    shifted_bits = bits[positions:] + bits[:positions]
    print(f'LS-{positions}:', shifted_bits)
    return shifted_bits

def xor_bits(bits1, bits2):
    """
    Realiza a operação XOR entre duas strings de bits
    """
    result = ""
    for b1, b2 in zip(bits1, bits2):
        if b1 == b2:
            result += "0"
        else:
            result += "1"
    print('XOR:', result)
    return result

def apply_sbox(bits, sbox, sbox_name):
    """
    Aplica a substituição da S-box
    Linha é determinada pelos bits externos (1º e 4º)
    Coluna é determinada pelos bits internos (2º e 3º)
    """
    #calcula o índice da linha usando o primeiro e último bit, bem como o índice da coluna usando os bits do meio
    row = int(bits[0] + bits[3], 2)
    col = int(bits[1] + bits[2], 2)
    
    #converte o valor da S-box para binário de 2 bits
    sbox_value = sbox[row][col]
    binary_value = format(sbox_value, '02b')
    
    print(f'{sbox_name}: {binary_value}')
    return binary_value

def generate_subkeys(key):
    """
    Gera duas subchaves de 8 bits (K1 e K2) a partir da chave de entrada de 10 bits
    """
    
    #Tabelas de permutação
    P10_TABLE = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8_TABLE = [6, 3, 7, 4, 8, 5, 10, 9]
    
    #Aplica a permutação P10
    key = permute(key, P10_TABLE, 'P10')
    
    #Divide em duas metades
    left = key[:5]
    right = key[5:]
    # print('Divisão da chave - Esquerda:', left, 'Direita:', right)
    
    #Gera K1: realiza LS-1 e depois P8
    left_k1 = left_shift(left, 1)
    right_k1 = left_shift(right, 1)
    k1 = permute(left_k1 + right_k1, P8_TABLE, 'P8')
    
    #Gera K2: realiza LS-2 e depois P8
    left_k2 = left_shift(left_k1, 2)
    right_k2 = left_shift(right_k1, 2)
    k2 = permute(left_k2 + right_k2, P8_TABLE, 'P8')
    
    print(f"\nSubchaves geradas: K1={k1}, K2={k2}")
    return k1, k2

def function_fk(bits, subkey, round_num):
    """
    Implementação da função complexa fK
    """
    print(f"\nExecutando função fK (Rodada {round_num})...")
    
    #Tabelas de permutação
    EP_TABLE = [4, 1, 2, 3, 2, 3, 4, 1]
    P4_TABLE = [2, 4, 3, 1]
    
    #S-Boxes
    S0 = [[1, 0, 3, 2],
          [3, 2, 1, 0],
          [0, 2, 1, 3],
          [3, 1, 3, 2]]
    
    S1 = [[0, 1, 2, 3],
          [2, 0, 1, 3],
          [3, 0, 1, 0],
          [2, 1, 0, 3]]
    
    #Expansão/Permutação
    expanded = permute(bits, EP_TABLE, 'EP')
    
    #XOR com a subchave
    xor_result = xor_bits(expanded, subkey)
    
    #divide para aplicação das S-boxes
    left = xor_result[:4]
    right = xor_result[4:]
    print('Divisão para S-boxes - Esquerda (S0):', left, 'Direita (S1):', right)
    
    #Aplica as S-boxes (matrizes)
    s0_result = apply_sbox(left, S0, 'S0')
    s1_result = apply_sbox(right, S1, 'S1')
    
    #combina os resultados e aplica P4
    combined = s0_result + s1_result
    print('Resultado combinado das S-boxes:', combined)
    
    final_result = permute(combined, P4_TABLE, 'P4')
    
    #aqui,acaba a função fK	
    return final_result

def sdes_encrypt(plaintext, key):
    """
    Realiza a encriptação S-DES.
    """    
    #Tabelas de permutação
    IP_TABLE = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV_TABLE = [4, 1, 3, 5, 7, 2, 8, 6]
    
    #gernado as subchaves
    k1, k2 = generate_subkeys(key)
    
    #Permutação inicial
    bits = permute(plaintext, IP_TABLE, 'IP')
    
    #metades esquerda e direita
    left = bits[:4]
    right = bits[4:]
    # print('Divisão inicial - Esquerda:', left, 'Direita:', right)
    
    #Primeira rodada
    f_output = function_fk(right, k1, 1)
    new_right = xor_bits(left, f_output)
    left = right
    right = new_right
    print('Após primeira rodada - Esquerda:', left, 'Direita:', right)
    
    #Segunda rodada
    f_output = function_fk(right, k2, 2)
    new_right = xor_bits(left, f_output)
    left = new_right
    print('Após segunda rodada - Esquerda:', left, 'Direita:', right)
    
    #Permutação final
    result = permute(left + right, IP_INV_TABLE, 'IP-1')
    print('Resultado da encriptação:', result)
    
    return result

def sdes_decrypt(ciphertext, key):
    """
    Realiza a decriptação S-DES (mesma estrutura da encriptação, mas com subchaves invertidas)
    """
    print("\nIniciando processo de decriptação...")
    
    #Tabelas de permutação
    IP_TABLE = [2, 6, 3, 1, 4, 8, 5, 7]
    IP_INV_TABLE = [4, 1, 3, 5, 7, 2, 8, 6]
    
    #Gera as subchaves
    k1, k2 = generate_subkeys(key)
    
    #Permutação inicial
    bits = permute(ciphertext, IP_TABLE, 'IP')
    
    #metades esquerda e direita
    left = bits[:4]
    right = bits[4:]
    print('Divisão inicial - Esquerda:', left, 'Direita:', right)
    
    #Primeira rodada (usando K2)
    f_output = function_fk(right, k2, 1)
    new_right = xor_bits(left, f_output)
    left = right
    right = new_right
    print('Após primeira rodada - Esquerda:', left, 'Direita:', right)
    
    #Segunda rodada (usando K1)
    f_output = function_fk(right, k1, 2)
    new_right = xor_bits(left, f_output)
    left = right
    right = new_right
    print('Após segunda rodada - Esquerda:', left, 'Direita:', right)
    
    #Permutação final
    result = permute(left + right, IP_INV_TABLE, 'IP-1')
    print('Resultado da decriptação:', result)
    
    return result

#testando
key = "1010000010"
plaintext = "11010111"
    
print(f"\nChave inicial: {key}")
print(f"Texto plano: {plaintext}")
    
#encriptação
ciphertext = sdes_encrypt(plaintext, key)
print(f"\nTexto cifrado: {ciphertext}")
    
#decriptação
decrypted = sdes_decrypt(ciphertext, key)
print(f"\nTexto decifrado: {decrypted}")
    
#verificação
print(f"\nEncriptação bem-sucedida: {plaintext == decrypted}")
