import sys

for line in open(sys.argv[1]).readlines():
    sys.stdout.write(line)
    sys.stderr.write(line)
