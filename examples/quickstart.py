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
#    d = card.request(gp.commands.GET_STATUS + b'\x80\x02' +
#      gp.card.encode("4F00"))
#    tlv = gp.tlv.TLV.deserialize(d)
#    print(tlv)
    print("ISD status:", card.get_status(gp.StatusKind.ISD))
    print("Apps and SDs:", card.get_status(gp.StatusKind.APP_SD))
    print("Load files & modules:", card.get_status(gp.StatusKind.LOAD_FILES_MOD))
    print("Load files only:", card.get_status(gp.StatusKind.LOAD_FILES))
