#!/bin/sh
SANITY_TESTS="santest_docopt.py santest_usergrps.py"

# run test_usergrps.py first to confirm a
# sane ini file we can rely on for subsequent testing
for SANTEST in $SANITY_TESTS
do
  /usr/bin/python3 $SANTEST -v || exit 1
done

for TEST in $(ls test_*.py)
do
  /usr/bin/python3 $TEST -v || exit 1
done
