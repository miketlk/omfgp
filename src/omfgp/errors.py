ERRORCODES = {
    b'\x62\x83': "The card is locked",  # in responce to select ISD command
    b'\x63\x00': "Authentication of host cryptogram failed",
    b'\x64\x00': "No specific diagnosis",
    b'\x65\x81': "Memory failure",
    b'\x67\x00': "Wrong length in Lc",
    b'\x68\x81': "Logical channel not supported or is not active",
    b'\x68\x82': "Secure messaging not supported",
    b'\x68\x83': "The last command of the chain was expected",
    b'\x69\x82': "Security status not satisfied",
    b'\x69\x85': "Conditions of use not satisfied",
    b'\x6A\x80': "Incorrect values in command data",
    b'\x6A\x81': "Function not supported (e.g. the card is locked)",
    b'\x6A\x82': "Application not found",
    b'\x6A\x84': "Not enough memory space",
    b'\x6A\x86': "Incorrect P1 P2",
    b'\x6A\x88': "Referenced data not found",
    b'\x6D\x00': "Invalid instruction",
    b'\x6E\x00': "Invalid class",
    b'\x94\x84': "Algorithm not supported",
    b'\x94\x85': "Invalid key check value"
}

SUCCESSCODES = {
    b'\x90\x00': "Success"
}

WARNINGCODES = {
    b'\x62\x00': "Logical Channel already closed",
    b'\x63\x10': "More data available"
}


def response_text(data):
    """Returns response text from full response data or SW1 & SW2 bytes"""
    sw = data[-2:]
    if sw[0] == 0x61:
        return "Response data incomplete, {} more bytes available"\
            "".format(sw[1])
    return SUCCESSCODES.get(
        sw, WARNINGCODES.get(sw, ERRORCODES.get(sw, "<unknown>"))
    )
