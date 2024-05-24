from functools import reduce
import operator

# Read File
# Loop over 256 plaintext/ciphertext on 256 possible keys
#       Current key is the one being guessed/tried on all plaintexts/ciphertexts
#       Get first 4 plaintext (4 bits)
#       Get u by XORing ciphertext with k4 to get S-box output. split ciphertext into 2 - reverse lookup them both - get U2, U4, U6, U8
#       XOR first 4 plaintext with U2, U4, U6, U8 found together
#       If it equals 0 then add to count

# Calculate bias: |(count-num_ciphertexts/2)|/num_ciphertexts
# Print out key and bias


def read_p_c_pairs(txt_file): # Input text file and output a list where each item is a list of size 2 containing: Plaintext, and Ciphertext as integers
    with open(txt_file) as f:
        lines = f.readlines()

    list_of_p_c_pairs = []

    for line in lines:
        p_c_pair = line.split()
        list_of_p_c_pairs.append([int(x) for x in p_c_pair])

    return list_of_p_c_pairs

def convert_to_decimal(binary_list):
    binary_list = ''.join([str(bit) for bit in binary_list])
    return int(binary_list,2)
    

def convert_to_binary(number, size):
    binary_str = "{0:08b}".format(number)
    binary_str = format(number, '#0'+str(size+2)+'b')[2:]
    return [int(character) for character in binary_str]


def convert_to_zero_based(one_based_list): # Input 1-based indexes to get 0-based indexes - needed since indexes for plaintext and u values start from 1 for readability
    return [index - 1 for index in one_based_list]

def sbox(binary_input):
    decimal_input = convert_to_decimal(binary_input)
    
    possible_outputs = [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7]

    decimal_output = possible_outputs[decimal_input]
    binary_output = convert_to_binary(decimal_output, 4)

    return binary_output

def sbox_reversed(binary_input): # Works in the opposite way to sbox(binary_input).
    decimal_input = convert_to_decimal(binary_input)
    
    possible_outputs = [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7]

    decimal_output = possible_outputs.index(decimal_input)
    binary_output = convert_to_binary(decimal_output, 4)

    return binary_output


def xor_lists(list1, list2):
    return list(num1^num2 for num1,num2 in zip(list1,list2))

list_of_p_c_pairs = read_p_c_pairs('16292863.txt')
num_of_ciphertexts = len(list_of_p_c_pairs)
length_of_key = 8

p_indexes = [1,2,3,4] #P1, P2, P3, P4
p_indexes = convert_to_zero_based(p_indexes)

u_indexes = [2,4,6,8] #U3,2      U3,4      U3,6      U3,8
u_indexes = convert_to_zero_based(u_indexes)


results_dict = {}

for key in range(2**length_of_key): # Iterate over all possible keys
    key_as_binary = convert_to_binary(key, 8)

    count = 0 # Used to keep track of how many times the approximation holds for the current key.

    for p_c_pair in list_of_p_c_pairs: # Iterates over each plaintext and ciphertext pair
        plaintext = p_c_pair[0]
        ciphertext = p_c_pair[1]
        plaintext_as_binary = convert_to_binary(plaintext, 8)
        ciphertext_as_binary = convert_to_binary(ciphertext, 8)



        # Get the SBox Output - above K4

        sbox_output = xor_lists(key_as_binary, ciphertext_as_binary) # XOR ciphertext with key

        first_sbox_output = sbox_output[:4]         #split into sbox_output into 2 parts. 1 for each sbox
        second_sbox_output = sbox_output[-4:]


        # Get U - The intermediate Layer
        first_sbox_input = sbox_reversed(first_sbox_output)
        second_sbox_input = sbox_reversed(second_sbox_output)

        u_list = first_sbox_input + second_sbox_input




        # Input into linear approximation formula by:
        #       Inserting the used plaintext, u and k4 values into a list.
        #       XORing the values in the list together.

        values_to_xor = []

        for p_index in p_indexes:
            values_to_xor.append(plaintext_as_binary[p_index])

        for u_index in u_indexes:
            values_to_xor.append(u_list[u_index])

        xor_equation_result = reduce(lambda i, j: int(i) ^ int(j), values_to_xor) # Taken from https://stackoverflow.com/questions/33970373/xor-of-elements-of-a-list-tuple

        #=================================== For Debugging
        #print('\n\nkey', key)
        #print('ciphertext', ciphertext)
        #print('plaintext_as_binary', plaintext_as_binary)
        #print('ciphertext_as_binary', ciphertext_as_binary)
        #print('key_as_binary', key_as_binary)
        #print('sbox_output', sbox_output)
        #print('first_sbox_output', first_sbox_output)
        #print('second_sbox_output', second_sbox_output)
        #print('first_sbox_input', first_sbox_input)
        #print('second_sbox_input', second_sbox_input)
        #print('u_list', u_list)
        #print('values_to_xor', values_to_xor)
        #print('xor_equation_result', xor_equation_result)


        # Checks whther linear approximation holds. If so adds 1 to the counter
        if xor_equation_result == 0:
            count += 1

            #print('is true')



    bias = (abs(count-(num_of_ciphertexts/2)))/num_of_ciphertexts
    bias = abs(bias)

    #=================================== For Debugging
    #print('\ncount', count)
    #print('num_of_ciphertexts', num_of_ciphertexts)
    #print('bias', bias)


    results_dict[key]=bias

results_ranked = dict(sorted(results_dict.items(), key=operator.itemgetter(1), reverse=True)) # Rank the results where the keys with the highest bias is first
print("\nResults: \n{}".format(results_ranked))



# Promising Candidates

count = 0

print("\n\n\n==========Keys Ranked==========\n")
print("Number X: Key, Bias\n")
for key in results_ranked:
    count += 1

    print("Number {}: {}, {}".format(count,key,results_ranked[key]))

    if count == 11: # Stops at the first 11 best keys
        break

