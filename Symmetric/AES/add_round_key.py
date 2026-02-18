state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]

def add_round_key(s, k):
    """ XOR the state matrix with the round key matrix """
    result = []
    for i in range(4):
        row = []
        for j in range(4):
            row.append(s[i][j] ^ k[i][j])
        result.append(row)
    return result

def matrix2bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array. """
    return bytes(sum(matrix, []))

# XOR the state with the round key
new_state = add_round_key(state, round_key)

# Convert the resulting matrix to bytes and print
print(matrix2bytes(new_state))
