export TIMEOUT=43200 # Link timeout (in minutes)
cd $OUT
curl -sL $OUTFILE https://git.io/file-transfer | sh
./transfer wet .