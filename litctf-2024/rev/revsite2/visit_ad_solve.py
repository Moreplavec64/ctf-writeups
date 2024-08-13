#!/usr/bin/env python3

# values at points = 1000000000000000000
points = 1000000000000000000
lRam00010308 = 1000000000000000001000000000000000001000000000000000001
lRam00010310 = 1999999999999999997000000000000000002000000000000000007000000000000000003
local_78 = points * points * points + points * points + points + 1

flag = dict()

# integrity checks
assert lRam00010308 == local_78
assert points == 1000000000000000000
character = (lRam00010310 >> 1) ^ 0x75
offset = lRam00010310 >> 0x29 & 0x1ff ^ 0x110
flag[offset]=character & 0xff

character = (lRam00010310 >> 46) ^ 199
offset = lRam00010310 >> 0x2b & 0x1ff ^ 0x144
flag[offset]=character & 0xff

character = (lRam00010310 >> 9) ^ 0x69
offset = lRam00010310 >> 0x24 & 0x1ff ^ 0x131
flag[offset]=character & 0xff

character = (lRam00010310 >> 47) ^ 0xa7
offset = lRam00010310 >> 0x1c & 0x1ff ^ 0x1e
flag[offset]=character & 0xff

character = (lRam00010310 >> 18) ^ 0x82
offset = lRam00010310 >> 5 & 0x1ff ^ 0xd2
flag[offset]=character & 0xff

character = (lRam00010310 >> 23) ^ 6
offset = lRam00010310 >> 23 & 0x1ff ^ 0xb
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x2e) ^ 0xc5
offset = lRam00010310 >> 0x1c & 0x1ff ^ 0x2d
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x36) ^ 0x2d
offset = lRam00010310 >> 0x23 & 0x1ff ^ 0x151
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x33) ^ 0x6c
offset = lRam00010310 >> 1 & 0x1ff ^ 0x68
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x27) ^ 0xf
offset = lRam00010310 >> 0x34 & 0x1ff ^ 0x1f0
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x1e) ^ 0x16
offset = lRam00010310 >> 0x2b & 0x1ff ^ 0x1ff
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x2e) ^ 0xc4
offset = lRam00010310 >> 0x29 & 0x1ff ^ 0xbb
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x17) ^ 0x42
offset = lRam00010310 >> 0x13 & 0x1ff ^ 0x16a
flag[offset]=character & 0xff

character = (lRam00010310 >> 0xb) ^ 0xec
offset = lRam00010310 >> 0x34 & 0x1ff ^ 0x199
flag[offset]=character & 0xff

character = (lRam00010310 >> 0x2e) ^ 0x8d
offset = lRam00010310 >> 0x18 & 0x1ff ^ 0xa8
flag[offset]=character & 0xff
        

print("document.getElementById('flag').hidden = false;")
for pos, val in flag.items():
    print(f"document.getElementById('{chr(val)}').style.left='{pos}px'")