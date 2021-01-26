import sys
import omfgp as gp
import time
if gp.USES_USCARD:
    from uscard import Reader
    from machine import Pin


def get_default_reader():
    """Return default smart card reader."""
    if gp.USES_USCARD:
        return uscard.Reader(name="Smart card reader",
                             ifaceId=2,
                             ioPin=Pin.cpu.A2, clkPin=Pin.cpu.A4,
                             rstPin=Pin.cpu.G10, presPin=Pin.cpu.C2,
                             pwrPin=Pin.cpu.C5)
    else:
        return None


def card_status(card: gp.card.GPCard) -> list:
    """Display all kinds of smart card status information returning file list

    :param card: instance of smart card interface
    :return: list of load file AID
    """
    isd_status = card.get_status(gp.StatusKind.ISD)
    app_sd_status = card.get_status(gp.StatusKind.APP_SSD)
    file_mod_status = card.get_status(gp.StatusKind.LOAD_FILES_MOD)
    file_status = card.get_status(gp.StatusKind.LOAD_FILES)

    print("\n=== ISD status ===\n", isd_status, "\n")
    print("\n=== Apps and SDs ===\n", app_sd_status, "\n")
    print("\n=== Load files & modules ===\n", file_mod_status, "\n")
    print("\n=== Load files only ===\n", file_status, "\n")

    return [s.aid for s in file_status]


if __name__ == '__main__':
    # Loads applet to the card using first available reader and default keys
    # If the applet already exists it is deleted prior to load

    card = gp.card.GPCard(reader=get_default_reader(), debug=True)
    try:
        select_rsp = card.select()
        print("SELECT response:", select_rsp)

        card.open_secure_channel()
        card_file_aid_list = card_status(card)

        file = open("examples/teapot_applet.ijc", "rb")
        applet = gp.applet.Applet.read_from(file)

        if applet.package_aid in card_file_aid_list:
            print("Deleting load file '%s' and related applets" %
                  applet.package_aid)
            card.delete_object(applet.package_aid)

        card.load_applet(applet, target_sd_aid=select_rsp.aid)
        card_status(card)

    finally:
        card.disconnect()
