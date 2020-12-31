import omfgp as gp
import time

if __name__ == '__main__':
    # GP card instance using
    # first available reader
    # also opens connection to it
    card = gp.card.GPCard(debug=True)
    tlv = card.select()
    print(tlv)
    # 6f10
    #   8408
    #     a000000151000000
    #   a504
    #     9f6501
    #       ff
    ISD = tlv.get(0x6f, {}).get(0x84, b"")
    print("ISD AID:", ISD.hex())

    card.open_secure_channel()
    print("\n=== ISD status ===\n", card.get_status(gp.StatusKind.ISD), "\n")
    print("\n=== Apps and SDs ===\n", card.get_status(gp.StatusKind.APP_SSD),
          "\n")
    print("\n=== Load files & modules ===\n",
          card.get_status(gp.StatusKind.LOAD_FILES_MOD), "\n")
    print("\n=== Load files only ===\n",
          card.get_status(gp.StatusKind.LOAD_FILES), "\n")
