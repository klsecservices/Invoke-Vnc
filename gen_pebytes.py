
import sys
import base64
buf64 = open(sys.argv[1], 'rb').read()

buf32 = open(sys.argv[2], 'rb').read()

ps1_lines = open(sys.argv[3], 'rb').readlines()

with open(sys.argv[3], 'wb') as f:
	for line in ps1_lines:
		if '#replace64' in line:
			f.write("$PEBytes64 = '" + base64.b64encode(buf64) + "' #replace64\n")
		elif '#replace32' in line:
			f.write("$PEBytes32 = '" + base64.b64encode(buf32) + "' #replace32\n")
		else:
			f.write(line)


#
#print "$PEBytes32 = '" + base64.b64encode(buf32) + "'"
