ERRORCODES = {
	b"\x62\x83": "The card is locked", # in responce to select ISD command

	b"\x6A\x81": "Function not supported (e.g. the card is locked)",
	b"\x6A\x82": "Selected application not found",

	b"\x90\x00": "Success"
}