#!/bin/bash

# if -f FEATURE is passed, we can use the feature name to determine whether or
# not to start a server (default is to do so)
#if [[ $1 == "-f" ]] ; then
#    shift
#    FEATURE=$1
#    shift
#fi

EXE="../digduke"

function run_test {

    # parameters
    TAG=$1
    LINE=$(awk '$3 == "'${TAG}'"' itests.include | grep -v ^#)
    if [[ $LINE == "" ]] ; then
        echo "ERROR: tag ${TAG} not found in itests.include"
        return 127
    fi
    if [ $(echo $LINE | wc -l) != 1 ] ; then
        echo "ERROR: tag ${TAG} does not have a unique entry in itests.include"
        return 127
    fi
    FEATURE=$(echo $LINE | awk '{print $2}')
    ARGS=$(echo $LINE | cut -d'"' -f2)

    PTAG=$(printf '%-30s' "$TAG")

    # file paths
    OUTPUT=outputs/$TAG.txt
    FAIL=outputs/.$TAG.fail
    EXPECT=expected/$TAG.txt
    VALGRND=valgrind/$TAG.txt

    # TODO - this depends on the test being run!
    # run test and compare output to the expected version
    #/cs/home/stu-f/kirkpams/private/361/projects/dist/p2-fixed/tests/dukens -s 2 >/dev/null 2>&1 &
    if [[ "$FEATURE" =~ ^s.* ]] ; then
        if [[ "$TAG" =~ ^lookup* ]] ; then
            ../dukens $ARGS 2>/dev/null >"$OUTPUT"
        else
            # TODO: start student's server and run pre-built client
            ../dukens -s 2 2>/dev/null >"$OUTPUT" &
            sleep 1
            ./digduke $ARGS >/dev/null 2>&1
            sleep 3
        fi
    else
        ./dukens -s 2 >/dev/null 2>&1 &
        sleep 1
        ../digduke $ARGS 2>/dev/null >"$OUTPUT"
    fi

    EFILES="$EXPECT $(find expected -type f -name "$TAG-*.txt")"
    for EXP in $EFILES ; do
        DIFF=$(echo $EXP | sed 's/expected/outputs/' | sed 's/txt/diff/')
        diff -u "$OUTPUT" "$EXP" >"$DIFF"
        if [ ! -s "$DIFF" ]; then
            echo "$PTAG pass"
            rm outputs/$TAG*diff
            if [ -a $FAIL ] ; then
                rm $FAIL
            fi
            return 0
        fi
    done

    echo "$PTAG FAIL"
        printf '%4s' " "
        echo "Command line: $EXE $ARGS" | tee $FAIL
    return 1
}

# structure of itests.include:
# LEVEL FEATURE TEST "args"

if [[ $1 = "info" ]] ; then
    #     if LEVEL, "Grade level $LEVEL has $n features: $f1 ...
    #     if FEATURE, "Feature $FEATURE has $n tests: $t1 ...
    #     if TEST, "Test $TEST has arguments \"...\""
    echo "list all test cases"
    exit 0
fi

# initialize output folders
if [ ! -d "outputs" ] ; then
    mkdir -p outputs
fi
#if [ ! -d "valgrind" ] ; then
#  mkdir -p valgrind
#fi
#rm -f outputs/* valgrind/*

TESTS=$@

echo "----------------------------------------"
for t in $TESTS ; do
    run_test $t
    if [[ $? != 0 ]] ; then
        echo "----------------------------------------"
        #echo "ERROR: Stopping due to failing test $t"
        exit 1
    fi
done

echo "----------------------------------------"
echo "SUCCESS: All tests passed"
exit 0

# run individual tests
#source itests.include

# check for memory leaks
#LEAK=`cat valgrind/*.txt | grep 'definitely lost' | grep -v ' 0 bytes in 0 blocks'`
#if [ -z "$LEAK" ]; then
#    echo "No memory leak found."
#else
#    echo "Memory leak(s) found. See files listed below for details."
#    grep 'definitely lost' valgrind/*.txt | grep -v ' 0 bytes in 0 blocks' | sed -e 's/:.*$//g' | sed -e 's/^/  - /g'
#fi

