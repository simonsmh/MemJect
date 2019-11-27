import sys
import os

file = bytearray(open(sys.argv[1] if len(
    sys.argv) >= 2 else f'{os.path.split(os.path.realpath(__file__))[0]}\..\Osiris\Release\Osiris.dll', 'rb').read())

with open(sys.argv[2] if len(sys.argv) >= 3 else f'{os.path.split(os.path.realpath(__file__))[0]}\MemJect\self.h', 'w') as output:
    output.write('#pragma once\n#include <stdint.h>\nstatic uint8_t binary[]={\n')
    for count, byte in enumerate(file, 1):
        output.write(f'{byte:#0{4}x},' + ('\n' if not count % 16 else ' '))
    output.write('};')
