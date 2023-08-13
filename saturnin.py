'''
Created on Aug 9, 2023

@author: liyu0x
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher


class SaturninCipher(AbstractCipher):
    name = "saturnin"

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['S', 'P', 'w']

    def createSTP(self, stp_filename, parameters):

        word_size = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]

        if word_size != 256:
            print("Only wordsize of 256-bit supported.")
            exit(1)
        if rounds % 2 != 0:
            print("Only rounds of even number supported.")
            exit(1)

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% SATURNIN WordSize={}"
                      "rounds={}\n\n\n".format(word_size, rounds))
            stp_file.write(header)

            # Setup variables
            s = ["S{}".format(i) for i in range(rounds + 1)]
            p = ["P{}".format(i) for i in range(rounds)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, s, wordsize)
            stpcommands.setupVariables(stp_file, p, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            for i in range(rounds):
                self.setupPresentRound(stp_file, s[i], p[i], s[i + 1],
                                       w[i], wordsize)

            # No all zero characteristic
            stpcommands.assertNonZero(stp_file, s, wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, s[0], s[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            stpcommands.setupQuery(stp_file)

        return

    def setup_even_round(self, stp_file, s_in, p, alpha_1, alpha_2, s_out, w, word_size):
        """
        EVEN ROUND: 1. Sbox  2. MDS
        """
        command = ""

        even_nibble_index_s_box_0 = [0, 6, 14, 1, 15, 4, 7, 13, 9, 8, 12, 5, 2, 10, 3, 11]
        odd_nibble_index_s_box_1 = [0, 9, 13, 2, 15, 1, 11, 7, 6, 4, 5, 3, 8, 12, 10, 14]

        # coordinate(x,y,z) , a nibble is from y+4*x+16*z to y+4x+16z+3

        # Sbox
        for x in range(4):
            for y in range(4):
                for z in range(4):
                    nibble_index = y + 4 * x + 16 * z
                    variables = ["{0}[{1}:{1}]".format(s_in, nibble_index + 3),
                                 "{0}[{1}:{1}]".format(s_in, nibble_index + 2),
                                 "{0}[{1}:{1}]".format(s_in, nibble_index + 1),
                                 "{0}[{1}:{1}]".format(s_in, nibble_index + 0),
                                 "{0}[{1}:{1}]".format(p, nibble_index + 3),
                                 "{0}[{1}:{1}]".format(p, nibble_index + 2),
                                 "{0}[{1}:{1}]".format(p, nibble_index + 1),
                                 "{0}[{1}:{1}]".format(p, nibble_index + 0),
                                 "{0}[{1}:{1}]".format(w, nibble_index + 3),
                                 "{0}[{1}:{1}]".format(w, nibble_index + 2),
                                 "{0}[{1}:{1}]".format(w, nibble_index + 1),
                                 "{0}[{1}:{1}]".format(w, nibble_index + 0)]
                    present_s_box = even_nibble_index_s_box_0 if nibble_index % 2 == 0 else odd_nibble_index_s_box_1
                    command += stpcommands.add4bitSbox(present_s_box, variables)

        # MDS nibbles (4i,4i+1,4i+2,4i+3)
        for i in range(16):
            a = p[4 * i + 0:4 * i + 0 + 3]
            b = p[4 * i + 1:4 * i + 1 + 3]
            c = p[4 * i + 2:4 * i + 2 + 3]
            d = p[4 * i + 3:4 * i + 3 + 3]
            a1 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])
            a2 = msd_alpha_2(a, alpha_2[4 * i + 0:4 * i + 0 + 3])
            b1 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])
            b2 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])
            c1 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])
            c2 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])
            d1 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])
            d2 = msd_alpha_1(a, alpha_1[4 * i + 0:4 * i + 0 + 3])

        stp_file.write(command)
        return


# -------------------------------------------

def xor(_ins: list, _out):
    template = "BVXOR({0}, {1})"
    express = _ins[0]
    for i in range(1, len(_ins)):
        _in = _ins[i]
        express = template.format(_in, express)
    return "ASSERT({0}={1});".format(_out, express)


def msd_alpha_1(_in: list, _out: list):
    commend = "ASSERT({0} = {1});".format(_out[0], _in[1])
    commend += "ASSERT({0} = {1});".format(_out[1], _in[2])
    commend += "ASSERT({0} = {1});".format(_out[2], _in[3])
    commend += "ASSERT({0} = BVXOR({1},{2}));".format(_out[3], _in[0], _in[1])
    return commend


def msd_alpha_2(_in: list, _out: list):
    commend = "ASSERT({0} = {1});".format(_out[0], _in[2])
    commend += "ASSERT({0} = {1});".format(_out[1], _in[3])
    commend += "ASSERT({0} = BVXOR({1},{2}));".format(_out[2], _in[0], _in[1])
    commend += "ASSERT({0} = BVXOR({1},{2}));".format(_out[3], _in[1], _in[2])
    return commend
