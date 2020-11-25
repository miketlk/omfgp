from io import BytesIO

TAGS = {
	(0x6f, 0x84): "ISD AID", # Issuer security domain applet ID
	(0x6f, 0xa5): None, # unknown
	
}

class TLV(dict):
	@classmethod
	def deserialize(cls, b, levels=1):
		s = BytesIO(b)
		o = {}
		while True:
			k = s.read(1)
			if len(k) == 0:
				break
			l = s.read(1)
			if len(l) == 0:
				raise RuntimeError("Not TLV, can't read length")
			l = l[0]
			v = s.read(l)
			if len(v) != l:
				raise RuntimeError("Not TLV, can't read value")
			if levels > 1:
				v = TLV.deserialize(v, levels-1)
			o[k[0]] = v
		return cls(o)

	def serialize(self):
		r = b""
		for k in self.keys():
			v = self[k]
			if hasattr(v, "serialize"):
				v = v.serialize()
			r += bytes([k, len(v)]) + v
