import string

class Rotor:
    def __init__(self, wiring, position=0):
        self.wiring = wiring  # Wiring is a list of tuples (e.g., [[23, 13], ...])
        self.position = position
        self.wiring_letters = ""
        self.alphabet = string.ascii_uppercase

        for index in range(len(self.wiring)):
            letter_index = self.wiring[index][0]
            for index2 in range(len(self.wiring)):
                letter_index2 = self.wiring[index2][1]
                if letter_index == letter_index2:
                    self.wiring_letters += self.alphabet[index2]
                    break
        print(f"Rotor creation, letter-mapping: {self.wiring_letters}")

    def encode_forward(self, letter):
        # Convert letter to its index
        alphabet = string.ascii_uppercase
        letter_index = alphabet.index(letter)
        print(f"Transformation is {letter} to {self.wiring_letters[letter_index]}")

        return self.wiring_letters[letter_index]

    def rotate(self, number=0):
        # Rotate rotor by moving the wiring by one position (move last to front)
        self.position = (self.position + 1) % 26
        self.wiring = [self.wiring[-1]] + self.wiring[:-1]
        self.wiring_letters = ""
        for index in range(len(self.wiring)):
            letter_index = self.wiring[index][0]
            for index2 in range(len(self.wiring)):
                letter_index2 = self.wiring[index2][1]
                if letter_index == letter_index2:
                    self.wiring_letters += self.alphabet[index2]
                    break

        print(f"\nNew wiring for rotor {number+1}: {self.wiring}")
        print(f"New letters: {self.wiring_letters}")


class RotorMachine:
    def __init__(self, rotors, count=0):
        self.rotors = rotors
        self.count = count

    def encrypt(self, plaintext):
        ciphertext = ''
        for letter in plaintext:
            if letter not in string.ascii_uppercase:
                ciphertext += letter  # Ignore non-alphabet characters
                continue


            # Step 2: Forward pass through the rotors
            signal = letter
            for rotor in self.rotors:
                signal = rotor.encode_forward(signal)

            # Step 3: Append the result to ciphertext
            ciphertext += signal
            self.rotors[0].rotate(0)
            self.count += 1
            if self.count % 26 == 0:
                self.rotors[1].rotate(1)
            if self.count % (26*26) == 0:
                self.rotors[2].rotate(2)

        return ciphertext


# Define the wiring for the three rotors
rotor_1_wiring = [
    [23, 13], [24, 21], [25, 3], [26, 15], [1, 1], [2, 19], [3, 10], [4, 14],
    [5, 26], [6, 20], [7, 8], [8, 16], [9, 7], [10, 22], [11, 4], [12, 11],
    [13, 5], [14, 17], [15, 9], [16, 12], [17, 23], [18, 18], [19, 2], [20, 25],
    [21, 6], [22, 24]
]

rotor_2_wiring = [
    [26, 20], [1, 1], [2, 6], [3, 4], [4, 15], [5, 3], [6, 14], [7, 12],
    [8, 23], [9, 5], [10, 16], [11, 2], [12, 22], [13, 19], [14, 11], [15, 18],
    [16, 25], [17, 24], [18, 13], [19, 7], [20, 10], [21, 8], [22, 21], [23, 9],
    [24, 26], [25, 17]
]
rotor_3_wiring = [
    [1, 8], [2, 18], [3, 26], [4, 17], [5, 20], [6, 22], [7, 10], [8, 3],
    [9, 13], [10, 11], [11, 4], [12, 23], [13, 5], [14, 24], [15, 9], [16, 12],
    [17, 25], [18, 16], [19, 19], [20, 6], [21, 15], [22, 21], [23, 2], [24, 7],
    [25, 1], [26, 14]
]

# Create the rotors
rotor_1 = Rotor(rotor_1_wiring)
rotor_2 = Rotor(rotor_2_wiring)
rotor_3 = Rotor(rotor_3_wiring)

# Assemble the rotor machine
machine = RotorMachine([rotor_1, rotor_2, rotor_3], count=673)

# Example usage
plaintext = "PERSPICACIOUS"
ciphertext = machine.encrypt(plaintext)
print(f"Plaintext:  {plaintext}")
print(f"Ciphertext: {ciphertext}")
