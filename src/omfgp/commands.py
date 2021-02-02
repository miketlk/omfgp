"""Global Platform specific commands"""

# Request data from the card
GET_RESPONSE = b'\x00\xC0'
# Select an applet
SELECT = b'\x00\xA4'
# Initialize a secure channel
INITIALIZE_UPDATE = b'\x80\x50'
# Authenticate the host and determine the security level
EXTERNAL_AUTHENTICATE = b'\x84\x82'
# Retrieve status of an on-card entity
GET_STATUS = b'\x80\xF2'
# Initiate or perform the various steps required for card content management
INSTALL = b'\x80\xE6'
# Transfer part of a load file to the card
LOAD = b'\x80\xE8'
# Delete a uniquely identifiable object and its related applications or a key
DELETE = b'\x80\xE4'

# Offset of the CLA byte within APDU
OFF_CLA = 0
# Offset of the INS byte within APDU
OFF_INS = 1
# Offset of the P1 byte within APDU
OFF_P1 = 2
# Offset of the P2 byte within APDU
OFF_P2 = 3
# Offset of the Lc byte within APDU
OFF_LC = 4
# Offset of the Data field within APDU
OFF_DATA = 5

# Maximum allowed value of LC field to fit the APDU into one T=1 frame
LC_MAX = 248

class ClaBits:
    """Bits of the class byte"""
    # GlobalPlatform command
    GP = 0b10000000
    # Further Interindustry class byte coding is used
    FURTHER = 0b01000000

    class First:
        """First Interindustry Class Byte Coding"""
        # Secure messaging - GlobalPlatform proprietary
        GP_SECURE = 0b00000100
        # Secure messaging - ISO/IEC 7816 standard, header not processed
        ISO_SECURE = 0b00001000
        # Secure messaging - ISO/IEC 7816 standard, header authenticated
        ISO_SECURE_MAC = 0b00001100
        # Mask for logical channel number
        LC_MASK = 0b00000011

    class Further:
        """Further Interindustry Class Byte Coding"""
        # Secure messaging - ISO/IEC 7816 or GlobalPlatform proprietary
        SECURE = 0b00100000
        # Mask for logical channel number
        LC_MASK = 0b00001111

