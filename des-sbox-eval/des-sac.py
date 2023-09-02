#!/usr/bin/env python
#
# Evaluate SAC (Strict Avalanche Criterion) for DES s-box
#
# Background:
# - https://datawok.net/posts/feistel-ciphers/#s-box
# - https://link.springer.com/chapter/10.1007/3-540-39799-X_41#page-1


# Preimage bits = 6
# Image bits = 4
sbox = [
    [
        14,  0,  4, 15, 13,  7,  1,  4,  2, 14, 15,  2, 11, 13,  8,  1,
         3, 10, 10,  6,  6, 12, 12, 11,  5,  9,  9,  5,  0,  3,  7,  8,
         4, 15,  1, 12, 14,  8,  8,  2, 13,  4,  6,  9,  2,  1, 11,  7,
        15,  5, 12, 11,  9,  3,  7, 14,  3, 10, 10,  0,  5,  6,  0, 13
    ],
    [
        15,  3,  1, 13,  8,  4, 14,  7,  6, 15, 11,  2,  3,  8,  4, 14,
         9, 12,  7,  0,  2,  1, 13, 10, 12,  6,  0,  9,  5, 11, 10,  5,
         0, 13, 14,  8,  7, 10, 11,  1, 10,  3,  4, 15, 13,  4,  1,  2,
         5, 11,  8,  6, 12,  7,  6, 12,  9,  0,  3,  5,  2, 14, 15,  9
    ],
    [
        10, 13,  0,  7,  9,  0, 14,  9,  6,  3,  3,  4, 15,  6,  5, 10,
         1,  2, 13,  8, 12,  5,  7, 14, 11, 12,  4, 11,  2, 15,  8,  1,
        13,  1,  6, 10,  4, 13,  9,  0,  8,  6, 15,  9,  3,  8,  0,  7,
        11,  4,  1, 15,  2, 14, 12,  3,  5, 11, 10,  5, 14,  2,  7, 12
    ],
    [
         7, 13, 13,  8, 14, 11,  3,  5,  0,  6,  6, 15,  9,  0, 10,  3,
         1,  4,  2,  7,  8,  2,  5, 12, 11,  1, 12, 10,  4, 14, 15,  9,
        10,  3,  6, 15,  9,  0,  0,  6, 12, 10, 11,  1,  7, 13, 13,  8,
        15,  9,  1,  4,  3,  5, 14, 11,  5, 12,  2,  7,  8,  2,  4, 14
    ],
    [
         2, 14, 12, 11,  4,  2,  1, 12,  7,  4, 10,  7, 11, 13,  6,  1,
         8,  5,  5,  0,  3, 15, 15, 10, 13,  3,  0,  9, 14,  8,  9,  6,
         4, 11,  2,  8,  1, 12, 11,  7, 10,  1, 13, 14,  7,  2,  8, 13,
        15,  6,  9, 15, 12,  0,  5,  9,  6, 10,  3,  4,  0,  5, 14,  3
    ],
    [
        12, 10,  1, 15, 10,  4, 15,  2,  9,  7,  2, 12,  6,  9,  8,  5,
         0,  6, 13,  1,  3, 13,  4, 14, 14,  0,  7, 11,  5,  3, 11,  8,
         9,  4, 14,  3, 15,  2,  5, 12,  2,  9,  8,  5, 12, 15,  3, 10,
         7, 11,  0, 14,  4,  1, 10,  7,  1,  6, 13,  0, 11,  8,  6, 13
    ],
    [
         4, 13, 11,  0,  2, 11, 14,  7, 15,  4,  0,  9,  8,  1, 13, 10,
         3, 14, 12,  3,  9,  5,  7, 12,  5,  2, 10, 15,  6,  8,  1,  6,
         1,  6,  4, 11, 11, 13, 13,  8, 12,  1,  3,  4,  7, 10, 14,  7,
        10,  9, 15,  5,  6,  0,  8, 15,  0, 14,  5,  2,  9,  3,  2, 12
    ],
    [
        13,  1,  2, 15,  8, 13,  4,  8,  6, 10, 15,  3, 11,  7,  1,  4,
        10, 12,  9,  5,  3,  6, 14, 11,  5,  0,  0, 14, 12,  9,  7,  2,
         7,  2, 11,  1,  4, 14,  1,  7,  9,  4, 12, 10, 14,  8,  2, 13,
         0, 15,  6, 12, 10,  9, 13,  0, 15,  3,  3,  5,  5,  6,  8, 11
    ]
]


def apply_box(box, x):
    """Applies the given substitution 'box' to the value 'x'"""
    row = (x & 0b100000) >> 4 | (x & 0b000001)
    col = (x & 0b011110) >> 1
    return box[row * 16 + col]


def bit_diff(a, b):
    """Get the bits changed as a value from 0 to 1"""
    count = 0;
    r = a ^ b
    # Image is 4 bits, so just consider the lowest 4 bits
    for i in range(0, 4):
        if r & 1 != 0:
            count += 1
        r >>= 1
    # Normalize as a value between 0 and 1
    return round(count / 4.0, 2)


def test_x(box, x):
    """Get mean value of changed bits by toggling one bit of x according to the box"""
    # Get the image for x according to the box
    y = apply_box(box, x)

    # Iterate over the all the input bits
    diffs = []
    for i in range(0, 6):
        # Toggle the i-th input bit
        x1 = x ^ (1 << i)
        # Get the image for x1 according to the box
        y1 = apply_box(box, x1)
        # Get the amount of changed bits as a value from 0 to 1
        diff = bit_diff(y, y1)
        diffs.append(diff)
    # Retun the mean of changed bits as a value from 0 to 1
    tot = 0
    for diff in diffs:
        tot += diff
    return tot / 6.0


def box_sac(box):
    tot = 0
    # Test the box for each possible block value x
    for x in range(0, 64):
        tot += test_x(box, x)
    return tot / 64.0


def box_sac_by_index(idx):
    return box_sac(get_box(idx))


def box_print(box):
    for i in range(0, len(box)):
        if i % 16 == 0:
            print()
        print("{:02x}".format(box[i]), end = " "),
    print()


def box_print_by_index(idx):
    box_print(get_box(idx))
    

def test_full_sbox():
    """Test SAC property for the whole SBOX table"""
    for i in range(0, len(sbox)):
        print("========================================")
        box = get_box(i)
        box_print(box)
        sac_value = box_sac(box)
        print("SAC VALUE: ", sac_value)

    
def get_box(idx):
    """Get the substitution box with the given index"""
    num_boxes = len(sbox)
    if idx >= num_boxes:
        idx = num_boxes - 1
        print("No such box, fallback to box {}".format(idx))
    return sbox[idx]


if __name__ == "__main__":
    test_full_sbox()
