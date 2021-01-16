import omfgp as gp
import time


def card_status(card):
    print("\n=== ISD status ===\n", card.get_status(gp.StatusKind.ISD), "\n")
    app_sd_status = card.get_status(gp.StatusKind.APP_SSD)
    print("\n=== Apps and SDs ===\n", app_sd_status, "\n")
    print("\n=== Load files & modules ===\n",
          card.get_status(gp.StatusKind.LOAD_FILES_MOD), "\n")
    print("\n=== Load files only ===\n",
          card.get_status(gp.StatusKind.LOAD_FILES), "\n")

    return [s.aid for s in app_sd_status]


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
    isd_aid = tlv.get(0x6f, {}).get(0x84, b"")
    print("ISD AID:", isd_aid.hex())

    card.open_secure_channel()
    card_aid_list = card_status(card)

    file = open("examples/teapot_applet.ijc", "rb")
    applet = gp.applet.Applet.read_from(file)
    if any(e in card_aid_list for e in applet.applet_aid_list):
        card.disconnect()
        raise RuntimeError("Applet already loaded")

    card.load_applet(applet, target_sd_aid=isd_aid)
    card_status(card)
    card.disconnect()
