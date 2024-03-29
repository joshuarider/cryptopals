package cracker

var (
	letterFreq = map[byte]float64{
		byte(65): 0.08167, // 'A'
		byte(66): 0.01492, // 'B'
		byte(67): 0.02782, // 'C'
		byte(68): 0.04253, // 'D'
		byte(69): 0.12702, // 'E'
		byte(70): 0.02228, // 'F'
		byte(71): 0.02015, // 'G'
		byte(72): 0.06094, // 'H'
		byte(73): 0.06966, // 'I'
		byte(74): 0.00153, // 'J'
		byte(75): 0.00772, // 'K'
		byte(76): 0.04025, // 'L'
		byte(77): 0.02406, // 'M'
		byte(78): 0.06749, // 'N'
		byte(79): 0.07507, // 'O'
		byte(80): 0.01929, // 'P'
		byte(81): 0.00095, // 'Q'
		byte(82): 0.05987, // 'R'
		byte(83): 0.06327, // 'S'
		byte(84): 0.09056, // 'T'
		byte(85): 0.02758, // 'U'
		byte(86): 0.00978, // 'V'
		byte(87): 0.02360, // 'W'
		byte(88): 0.00150, // 'X'
		byte(89): 0.01974, // 'Y'
		byte(90): 0.00074, // 'Z'
		byte(32): 0.17000, // 'SPACE'
		byte(33): 0.17000, // '!'
		byte(34): 0.00000, // '"'
		byte(39): 0.00000, // "'"
		byte(44): 0.00000, // ','
		byte(45): 0.00000, // '-'
		byte(46): 0.00000, // '.'
		byte(47): 0.00000, // '/'
		byte(48): 0.00000, // '0'
		byte(49): 0.00000, // '1'
		byte(50): 0.00000, // '2'
		byte(51): 0.00000, // '3'
		byte(52): 0.00000, // '4'
		byte(53): 0.00000, // '5'
		byte(54): 0.00000, // '6'
		byte(55): 0.00000, // '7'
		byte(56): 0.00000, // '8'
		byte(57): 0.00000, // '9'
		byte(58): 0.00000, // ':'
		byte(59): 0.00000, // ';'
		byte(10): 0.00000, // '\n'
		byte(13): 0.00000, // '\r'
	}
)
