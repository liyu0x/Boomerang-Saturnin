'''
Created on Mar 28, 2014

@author: stefan
'''

from parser import stpcommands
from ciphers.cipher import AbstractCipher

from parser.stpcommands import getStringLeftRotate as rotl


class SimonCipher(AbstractCipher):
    """
    Represents the differential behaviour of SIMON and can be used
    to find differential characteristics for the given parameters.
    """

    name = "simon"
    rot_alpha = 8
    rot_beta = 1
    rot_gamma = 2

    def left_rotate_array(self, arr, n):
        n = n % len(arr)
        return arr[n:] + arr[:n]

    def non_linear_part(self, x):
        x0 = x >> 1 & 0x1
        x1 = x & 0x1
        return x0 & x1

    def bct_vari(self, x_in, x_out, word_size):
        ori = [i for i in range(word_size)]
        alpha_vari = self.left_rotate_array(ori, self.rot_alpha)
        beta_vari = self.left_rotate_array(ori, self.rot_beta)
        variables = []
        for i in range(word_size):
            variable = ["{0}[{1}:{1}]".format(x_in, alpha_vari[i]),
                        "{0}[{1}:{1}]".format(x_in, beta_vari[i]),
                        "{0}[{1}:{1}]".format(x_out, alpha_vari[i]),
                        "{0}[{1}:{1}]".format(x_out, beta_vari[i])]
            variables.append(variable)

        return variables

    def getFormatString(self):
        """
        Returns the print format.
        """
        return ['XL', 'XR', 'YL', 'YR', 'w']

    def createSTP(self, stp_filename, parameters):
        """
        Creates an STP file to find a characteristic for SIMON with
        the given parameters.
        """

        wordsize = parameters["wordsize"]
        rounds = parameters["rounds"]
        weight = parameters["sweight"]
        switch_start_round = parameters["switchStartRound"]
        switch_rounds = parameters["switchRounds"]

        e0_start_search_num = 0
        e0_end_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_start_search_num = rounds if switch_start_round == -1 else switch_start_round
        em_end_search_num = rounds if switch_start_round == -1 else em_start_search_num + switch_rounds
        e1_start_search_num = rounds if switch_start_round == -1 else switch_start_round + switch_rounds
        e1_end_search_num = rounds

        # Replace with custom if set in parameters.
        if "rotationconstants" in parameters:
            self.rot_alpha = parameters["rotationconstants"][0]
            self.rot_beta = parameters["rotationconstants"][1]
            self.rot_gamma = parameters["rotationconstants"][2]

        with open(stp_filename, 'w') as stp_file:
            header = ("% Input File for STP\n% Simon w={} alpha={} beta={}"
                      " gamma={} rounds={}\n\n\n".format(wordsize,
                                                         self.rot_alpha,
                                                         self.rot_beta,
                                                         self.rot_gamma,
                                                         rounds))
            stp_file.write(header)
            command = ""
            # Setup variables
            # x = left, y = right
            xl = ["XL{}".format(i) for i in range(rounds + 1)]
            xr = ["XR{}".format(i) for i in range(rounds + 1)]
            yl = ["YL{}".format(i) for i in range(rounds + 1)]
            yr = ["YR{}".format(i) for i in range(rounds + 1)]

            and_out = ["andout{}".format(i) for i in range(rounds + 1)]

            and_out_t = ["andoutt{}".format(i) for i in range(rounds + 1)]

            # w = weight
            w = ["w{}".format(i) for i in range(rounds)]

            stpcommands.setupVariables(stp_file, xl, wordsize)
            stpcommands.setupVariables(stp_file, xr, wordsize)
            stpcommands.setupVariables(stp_file, yl, wordsize)
            stpcommands.setupVariables(stp_file, yr, wordsize)
            stpcommands.setupVariables(stp_file, and_out, wordsize)
            stpcommands.setupVariables(stp_file, and_out_t, wordsize)
            stpcommands.setupVariables(stp_file, w, wordsize)

            stpcommands.setupWeightComputation(stp_file, weight, w, wordsize)

            # E0
            for i in range(e0_start_search_num, e0_end_search_num):
                self.setupSimonRound(stp_file, xl[i], xr[i], xl[i + 1], xr[i + 1],
                                     and_out[i], w[i], wordsize)
            # Em
            for i in range(em_start_search_num, em_end_search_num):
                self.setupSimonRound(stp_file, xl[i], xr[i], xl[i + 1], xr[i + 1],
                                     and_out[i], w[i], wordsize, True)
                variable_arr = self.bct_vari(xr[i + 1], yr[i + 1], wordsize)
                command += self.and_bct(variable_arr, self.non_linear_part, 2)
                if parameters['mode'] != 4:
                    command += "ASSERT({0}={1});\n".format(yl[i+1], xl[i+1])

            # E1
            for i in range(e1_start_search_num, e1_end_search_num):
                self.setupSimonRound(stp_file, yl[i], yr[i], yl[i + 1], yr[i + 1],
                                     and_out_t[i], w[i], wordsize)

            # No all zero characteristic
            if switch_start_round == -1:
                stpcommands.assertNonZero(stp_file, xl + xr, wordsize)
            else:
                stpcommands.assertNonZero(stp_file, xl[e0_start_search_num:em_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, xr[e0_start_search_num:em_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, yl[em_start_search_num + 1:e1_end_search_num], wordsize)
                stpcommands.assertNonZero(stp_file, yr[em_start_search_num + 1:e1_end_search_num], wordsize)

            # Iterative characteristics only
            # Input difference = Output difference
            if parameters["iterative"]:
                stpcommands.assertVariableValue(stp_file, xl[0], xl[rounds])
                stpcommands.assertVariableValue(stp_file, xr[0], xr[rounds])

            for key, value in parameters["fixedVariables"].items():
                stpcommands.assertVariableValue(stp_file, key, value)

            for char in parameters["blockedCharacteristics"]:
                stpcommands.blockCharacteristic(stp_file, char, wordsize)

            command += self.pre_handle(parameters, em_start_search_num, em_end_search_num)
            stp_file.write(command)
            stpcommands.setupQuery(stp_file)

        return

    def setupSimonRound(self, stp_file, x_in, y_in, x_out, y_out, and_out, w,
                        wordsize, switch=False):
        """
        Model for differential behaviour of one round SIMON
        y[i+1] = x[i]
        x[i+1] = (x[i] <<< 1) & (x[i] <<< 8) ^ y[i] ^ (x[i] << 2)

        This model is only correct if gcd(self.rot_alpha - self.rot_beta, wordsize) = 1
        and self.rot_alpha > self.rot_beta
        """
        command = ""

        # Assert(y_out = x_in)
        command += "ASSERT({} = {});\n".format(y_out, x_in)

        x_in_rotalpha = rotl(x_in, self.rot_alpha, wordsize)
        x_in_rotbeta = rotl(x_in, self.rot_beta, wordsize)

        # Deal with dependent inputs
        varibits = "({0} | {1})".format(x_in_rotalpha, x_in_rotbeta)

        doublebits = self.getDoubleBits(x_in, wordsize)

        # Check for valid difference
        firstcheck = "({} & ~{})".format(and_out, varibits)
        secondcheck = "(BVXOR({}, {}) & {})".format(
            and_out, rotl(and_out, self.rot_alpha - self.rot_beta, wordsize), doublebits)
        thirdcheck = "(IF {0} = 0x{1} THEN BVMOD({2}, {3}, 0x{4}2) ELSE 0x{5} ENDIF)".format(
            x_in, "f" * (wordsize // 4), wordsize, and_out, "0" * (wordsize // 4 - 1),
                  "0" * (wordsize // 4))

        command += "ASSERT(({} | {} | {}) = 0x{});\n".format(
            firstcheck, secondcheck, thirdcheck, "0" * (wordsize // 4))

        # Assert XORs
        command += "ASSERT({} = BVXOR({}, BVXOR({}, {})));\n".format(
            x_out, rotl(x_in, self.rot_gamma, wordsize), y_in, and_out)

        if not switch:
            # Weight computation
            command += "ASSERT({0} = (IF {1} = 0x{4} THEN BVSUB({5},0x{4},0x{6}1) \
                        ELSE BVXOR({2}, {3}) ENDIF));\n".format(
                w, x_in, varibits, doublebits, "f" * (wordsize // 4),
                wordsize, "0" * ((wordsize // 4) - 1))
        else:
            command += 'ASSERT({}=0x0000);\n'.format(w)

        stp_file.write(command)
        return

    def getDoubleBits(self, x_in, wordsize):
        command = "({0} & ~{1} & {2})".format(
            rotl(x_in, self.rot_beta, wordsize),
            rotl(x_in, self.rot_alpha, wordsize),
            rotl(x_in, 2 * self.rot_alpha - self.rot_beta, wordsize))
        return command

    def and_bct(self, variables_arr, non_part, input_size):
        command = ""
        for varis in variables_arr:
            command += "ASSERT(BVXOR({0}&{1}, {2}&{3})=0bin0);\n".format(varis[0], varis[3], varis[1], varis[2])
        return command

    def and_bct_bak(self, variables_arr, non_part, input_size):
        bits = input_size
        size = 2 ** bits

        # create ^bct
        bct = [[0] * size for i in range(size)]
        for delta_in in range(size):
            for delta_out in range(size):
                for x in range(size):
                    x_delta_in = x ^ delta_in
                    x_delta_out = x ^ delta_out
                    x_delta_in_out = x ^ delta_in ^ delta_out
                    r_x = non_part(x)
                    r_x_delta_in = non_part(x_delta_in)
                    r_x_delta_out = non_part(x_delta_out)
                    r_x_delta_in_out = non_part(x_delta_in_out)
                    if r_x ^ r_x_delta_in ^ r_x_delta_out ^ r_x_delta_in_out == 0:
                        bct[delta_in][delta_out] += 1

        # Construct DNF of all valid trails
        trails = []
        # All zero trail with probability 1
        for input_diff in range(size):
            for output_diff in range(size):
                if bct[input_diff][output_diff] != 0:
                    tmp = []
                    for i in range(bits - 1, -1, -1):
                        tmp.append((input_diff >> i) & 1)
                    for i in range(bits - 1, -1, -1):
                        tmp.append((output_diff >> i) & 1)
                    trails.append(tmp)

        commands = ""
        for vars in variables_arr:
            command = "ASSERT({}@{}@{}@{}@=".format(vars[0], vars[1], vars[2], vars[3])
            for trail in trails:
                command += "0bin{}{}{}{}|".format(trail[0], trail[1], trail[2], trail[3])
            command = command[:-1]
            command += ")"
            commands += commands
        return commands

    def pre_handle(self, param, em_start, em_end):
        characters = param["bbbb"]
        command = ""
        if len(characters) > 0:
            r = param['rounds']
            command = "ASSERT(NOT("
            for characteristic in characters:
                trails_data = characteristic.getData()
                # input diff
                input_diff_l = trails_data[0][0]
                input_diff_r = trails_data[0][1]

                # output diff
                output_diff_l = trails_data[r][2]
                output_diff_r = trails_data[r][3]

                str1 = "(BVXOR(XL0,{0})|BVXOR(XR0, {1}) | BVXOR(YL{2}, {3}) | BVXOR(YR{2}, {4}))".format(input_diff_l,
                                                                                                         input_diff_r,
                                                                                                         r,
                                                                                                         output_diff_l,
                                                                                                         output_diff_r)
                command += str1
                command += "&"
            command = command[:-1]
            command += "=0x0000));\n"

        characters = param["cccc"]
        if len(characters) > 0:
            command = "ASSERT(NOT("
            for characteristic in characters:
                trails_data = characteristic.getData()

                # switch input diff
                input_diff_l = trails_data[em_start][0]
                # input_diff_r = trails_data[em_start][1]

                # switch output diff
                # output_diff_l = trails_data[em_end][2]
                output_diff_r = trails_data[em_end][3]

                str1 = "(BVXOR(XL{0},{1}) | BVXOR(YR{2}, {3}))".format(em_start,
                                                                       input_diff_l,
                                                                       em_end,
                                                                       output_diff_r)

                # str1 = "(BVXOR(XL{0},{1})|BVXOR(XR{0}, {2}) | BVXOR(YL{3}, {4}) | BVXOR(YR{3}, {5}))".format(em_start,
                #                                                                                              input_diff_l,
                #                                                                                              input_diff_r,
                #                                                                                              em_end,
                #                                                                                              output_diff_l,
                #                                                                                              output_diff_r)
                command += str1
                command += "&"
            command = command[:-1]
            command += "=0x0000));\n"
        return command

    def create_cluster_parameters(self, new_parameters, characteristic):
        r = new_parameters['rounds']
        # Cluster Search
        trails_data = characteristic.getData()
        new_parameters["blockedCharacteristics"].clear()
        new_parameters["fixedVariables"].clear()
        # input diff
        input_diff_l = trails_data[0][0]
        input_diff_r = trails_data[0][1]

        # output diff
        output_diff_l = trails_data[r][2]
        output_diff_r = trails_data[r][3]

        new_parameters["fixedVariables"]["XL0"] = input_diff_l
        new_parameters["fixedVariables"]["XR0"] = input_diff_r

        new_parameters["fixedVariables"]["YL{}".format(r)] = output_diff_l
        new_parameters["fixedVariables"]["YR{}".format(r)] = output_diff_r

    def get_diff_hex(self, parameters, characteristics):
        switch_start_round = parameters['switchStartRound']
        switch_rounds = parameters['switchRounds']
        r = parameters['rounds']
        trails_data = characteristics.getData()
        # input diff
        input_diff_l = trails_data[0][0]
        input_diff_r = trails_data[0][1]
        input_diff = input_diff_l + input_diff_r.replace("0x", "")

        # output diff
        output_diff_l = trails_data[r][2]
        output_diff_r = trails_data[r][3]
        output_diff = output_diff_l + output_diff_r.replace("0x", "")

        # switch diff
        switch_input_diff_l = trails_data[switch_start_round][0]
        switch_input_diff_r = trails_data[switch_start_round][1]
        switch_output_diff_l = trails_data[switch_start_round + switch_rounds][2]
        switch_output_diff_r = trails_data[switch_start_round + switch_rounds][3]
        switch_input = switch_input_diff_l + switch_input_diff_r.replace("0x", "")
        switch_output = switch_output_diff_l + switch_output_diff_r.replace("0x", "")

        return input_diff, switch_input, switch_output, output_diff
