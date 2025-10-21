#################################################################################################
# This file contains definitions for Fault characterization of Block ciphers
#################################################################################################
import re
from .cipherspec import CipherSpec

class FaultyCipher:
    """Represents a Block Cipher with faults injected.
    Used for finding maximum number of key bits that can be leaked and offline complexity.

    Attributes:
        cipher (CipherSpec)             : Cipher Specification object
        num_round_functions (int)       : Number of round functions in the block cipher
        num_parts (int)                 : Max number of parts in round function inputs
        is_linear_round (list[int])     : Linearity of the round functions
        dependencies (list[list[set[(int,int)]]])   : Input dependencies of each part
        color_matrix (list[list[int]])  : Color state of every part (0 indicates not colored)
        next_color (int)                : Next color value to use (that is not used before)
        derived                         : Set of Tuples about the derivable key bits and complexity
    """

    def __init__(self, cipher) -> None:
        """Creates a FaultCipher object

        Attributes:
            cipher (CipherSpec)                 : Cipher Specification object
        """
        self.cipher                             = cipher
        self.num_round_functions : int          = len(cipher.rounds)
        self.num_parts : int = max([len(round.parts) for round in cipher.rounds])
        self.color_matrix : list[list[int]]     = [[0 for _ in range(self.num_parts)]
                                                   for _ in range(self.num_round_functions+1)]
        self.next_color : int                   = 1
        self.derived = []    # Derived keys for each part

        self.is_linear_round = [True for _ in range(self.num_round_functions+1)]
        self.dependencies    = [[set() for _ in range(self.num_parts)]
                                for _ in range(self.num_round_functions+1)]
        for round_function_num, round in enumerate(cipher.rounds):
            if round.linearity == "nonlinear":
                self.is_linear_round[round_function_num+1] = False
            for part_num, part in enumerate(round.parts):
                for input_value in part.get_input_values():
                    m = re.match(r"F([0-9]+)\[([0-9]+)\]", input_value)
                    input_round_function_num = int(m.group(1))
                    input_part_num = int(m.group(2))
                    self.dependencies[round_function_num+1][part_num].add(
                            (input_round_function_num, input_part_num))

    def __str__(self) -> str:
        output = ""
        for i, round_colors in enumerate(self.color_matrix):
            output += "F" + str(i) + " "
            if self.is_linear_round[i]:
                output += "L "
            else:
                output += "NL"
            output += "\t:" + str(round_colors) + "\n"
        return output

    def set_fault(self, round_function_num : int, part_num : int):
        self.color_matrix[round_function_num][part_num] = self.next_color
        self.next_color += 1

    def propagate_faults(self):
        # Propagate the faults based on the input dependencies. 
        for round_function_num in range(1,self.num_round_functions+1):
            input_color_set = [set() for _ in range(self.num_parts)]
            for part_num in range(self.num_parts):
                for dependency in self.dependencies[round_function_num][part_num]:
                    input_color_set[part_num].add(self.color_matrix[dependency[0]][dependency[1]])

            if self.is_linear_round[round_function_num]:
                # Linear round
                for part_num in range(self.num_parts):
                    input_color_set[part_num].discard(0)
                    if len(input_color_set[part_num]) == 1:
                        self.color_matrix[round_function_num][part_num] = list(input_color_set[part_num])[0]
                    elif len(input_color_set[part_num]) > 1:
                        self.color_matrix[round_function_num][part_num] = self.next_color
                        self.next_color += 1
            else:
                # Non-Linear round
                for part_num in range(self.num_parts):
                    if len(input_color_set[part_num]) == 1 \
                            and list(input_color_set[part_num])[0] == 0:
                        pass
                    else:
                        self.color_matrix[round_function_num][part_num] = self.next_color
                        self.next_color += 1

    def find_dependant_colors(self, start_round_function_num, part_num):
        """Find all the colors that are recursively dependant on the given round function and part
        """
        dependency_set = set()
        dependency_set.add((start_round_function_num,part_num))

        terminate = False
        current_dependency_set = set()
        for current_round_num in range(start_round_function_num+1, self.num_round_functions+1):
            for part_num in range(self.num_parts):
                if len(self.dependencies[current_round_num][part_num]) > 2 \
                        or current_round_num == self.num_round_functions:
                    terminate = True
                for dependency in self.dependencies[current_round_num][part_num]:
                    if dependency in dependency_set:
                        current_dependency_set.add((current_round_num,part_num))
            dependency_set = current_dependency_set.copy()
            current_dependency_set.clear()

            if terminate:
                break

        dependant_colors = set()
        for dependency in dependency_set:
            dependency_round_function_num, dependency_part_num = dependency
            dependant_colors.add(self.color_matrix[dependency_round_function_num][dependency_part_num])
        return dependant_colors

    def determine_key_parts(self):
        H = 2.63    # S-Box differential characteristics for AES.
        W = 8       # Number of bits in a Part
        # FIXME How do we specify H & W for different ciphers?

        # Initialize data structures
        E = set()       # Set of colors which are already estimated
        # Set all ciphertext colors as estimated
        for part_num in range(self.num_parts):
            E.add(self.color_matrix[self.num_round_functions][part_num])
        theta = {}      # Map from Color to Search space
        theta[0] = 1
        for color in E:
            theta[color] = 1

        # Start estimating from the cipher text
        for round_function_num in reversed(range(1,self.num_round_functions+1)):
            if self.is_linear_round[round_function_num]:
                continue

            R = set()
            K = set()
            unknown_colors = set()
            R_count = {}
            for part_num in range(self.num_parts):
                # Since this is the Non-Linear S-Box layer, we assume there will be only one input
                assert(len(self.dependencies[round_function_num][part_num]) == 1)
                # Define x (input) and y (output) in the algorithm
                # The part_out is actually the input dependency of the part_in
                # In terms of color estimation, it is considered output
                part_in = (round_function_num, part_num)
                part_out = list(self.dependencies[round_function_num][part_num])[0]

                input_color = self.color_matrix[part_in[0]][part_in[1]]
                output_color = self.color_matrix[part_out[0]][part_out[1]]
                # Condition C1 : If the input color is already estimated
                C1 = input_color in E
                # Condition C2 : If the input color can be linearly expressed 
                #                   in terms of already estimated colors
                dependant_colors = self.find_dependant_colors(round_function_num, part_num)
                C2 = len(dependant_colors) > 0 and dependant_colors.issubset(E)

                if not (C1 or C2):
                    continue
                elif (not C1) and C2 and input_color != 0:
                    temp_theta = 1
                    for dependant_color in dependant_colors:
                        temp_theta = temp_theta * theta[dependant_color]
                else:
                    temp_theta = theta[input_color]

                if input_color != 0 and output_color != 0:
                    if output_color not in E:
                        theta_k = temp_theta * H * 2**W
                        unknown_colors.add(output_color)
                    elif output_color in unknown_colors:
                        theta_k = temp_theta * H * 2**W
                    else:
                        theta_k = temp_theta * H * theta[output_color]

                    theta[output_color] = theta_k
                    E.add(output_color)
                    K.add(part_num)
                    R.add(output_color)
                    if output_color not in R_count:
                        R_count[output_color] = 0
                    R_count[output_color] += 1

            theta_K_i = 1
            for color in R:
                theta_K_i = theta_K_i * theta[color]

            for unknown_color in unknown_colors:
                if unknown_color in R:
                    theta_K_i = min (theta_K_i, 256**(len(unknown_colors)))
                    break

            brute_force_complexity = (2**W)**len(K)
            for term in self.derived:
                (derived_round_function_num, derived_set, derived_theta_K_i) = term
                # FIXME +4 because of AES?
                if derived_round_function_num == round_function_num + 4 \
                        and theta_K_i < brute_force_complexity:
                    midvar = float(theta_K_i) / float(256**max(R_count.values()))
                    self.derived.append((derived_round_function_num, derived_set, \
                            int(derived_theta_K_i * midvar)))
                    self.derived.remove(term)
                    break
            if K and theta_K_i < brute_force_complexity:
                self.derived.append((round_function_num, K, theta_K_i))
            else:
                break

        # Find the maximum key bits that can be leaked and the corresponding complexity
        key_bits = 0
        offline_complexity = 0
        last_round_function = 0
        for (derived_round_function_num, derived_set, derived_theta_K_i) in self.derived:
            if derived_round_function_num > last_round_function:
                key_bits = len(derived_set) * W
                offline_complexity = derived_theta_K_i
                last_round_function= derived_round_function_num
        return (key_bits, offline_complexity)

    def reset_faults(self):
        """Reset the color matrix and get ready for another fault characterization run"""
        self.color_matrix = [[0 for _ in range(self.num_parts)]
                             for _ in range(self.num_round_functions+1)]
        self.next_color = 0

def get_fault_exploitability(cipher : CipherSpec, function_num : int, part_num : int):
    """Returns the maximum number of key bits derived, and offline complexity 
    when a fault is injected in the given block cipher at the given round function and part"""
    faulty_cipher = FaultyCipher(cipher)
    faulty_cipher.set_fault(function_num, part_num)
    faulty_cipher.propagate_faults()
    return faulty_cipher.determine_key_parts()
