import omfgp as gp
import time

if __name__ == '__main__':
    # GP card instance using
    # first available reader
    # also opens connection to it
    card = gp.card.GPCard(debug=True)
    d = card.select()
    tlv = gp.tlv.TLV.deserialize(d)
    print(tlv)
    # 6f10
    #   8408
    #     a000000151000000
    #   a504
    #     9f6501
    #       ff
    ISD = tlv.get(0x6f, {}).get(0x84, b"")
    print(ISD.hex())
