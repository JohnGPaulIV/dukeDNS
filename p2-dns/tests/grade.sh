#!/bin/bash

function print_report {
    REPORT=$1
    GRADE=$2

    printf "%s" "$REPORT"
    echo "----------------------------------------"
    echo "Current grade: $GRADE"
}

function build_report {
    BRD=$@
    for branch in $BRANCHES ; do
        PTAG=$(printf '%-30s' $branch)
        # if pattern matches, feature is already done and pushed
        if [[ "$BRD" == *"$branch-PASS"* ]] ; then
            REPORT+="$PTAG DONE"
            REPORT+=$'\n'
        else
            REPORT+="$PTAG incomplete"
            REPORT+=$'\n'
            BFAIL="$BFAIL $branch"
        fi
    done
}

function eval_grade {
    int=${BFAIL//"INTER"}
    intfail="$(((${#BFAIL} - ${#int}) / 5))"
    str=${BFAIL//"ADV"}
    strfail="$(((${#BFAIL} - ${#str}) / 3))"
    if [[ $BFAIL == *"BASIC"* ]] ; then
        GRADE="F"
        PREREQ=$(echo $BFAIL | tr ' ' $'\\n' | grep BASIC)
    elif [[ $BFAIL == *"MIN"* ]] ; then
        # D requires passing BASIC, but not MIN
        GRADE="D"
        PREREQ=$(echo $BFAIL | tr ' ' $'\\n' | grep MIN)
    else
        # passing all BASIC and MIN, so now reverse:
        if [[ $intfail -le 1 && $strfail -le 3 ]] ; then
            GRADE="A"
        elif [[ $intfail -le 2 && $strfail -le 4 ]] ; then
            GRADE="B"
        else
            GRADE="C"
        fi
    fi
}

# TODO: Set up these configuration parameters correctly
PROJ=p2-dns
USER=$(whoami)
REPOS=/cs/students/cs361/s26/kirkpams/projects/${USER}/${PROJ}
#REPOS=SUBMIT/${USER}/${PROJ}

# TODO: Change to using mktemp
# make a temp directory and go there
TEMP=$(mktemp -d)
cd $TEMP

# failsafe: should never happen
if [ -d $PROJ ] ; then
    echo "ERROR: Failed to make temp directory because $PROJ already exists"
    exit 128
fi

# clone the student's project repository
git clone $REPOS > /dev/null 2>&1
if [[ $? != 0 ]] ; then
    echo "ERROR: Failed to clone repository from $REPOS"
    echo "ERROR: Please make sure your submission repository is set up correctly"
    cd
    rm -rf $TEMP
    exit 1
fi

cd $PROJ

# Make sure the submission compiles
make > $TEMP/make.log 2>&1
if [[ $? != 0 ]] ; then
    echo "ERROR: Cloned version from $REPOS"
    echo "ERROR: Submitted code does not compile"
    cat $TEMP/make.log
    cd
    rm -rf $TEMP
    exit 1
fi

# Get the tests from a REF directory
cd tests

# First, check if the argument is valid
ITESTS=itests.include
FEATURE=$1
if [[ $FEATURE != "status" && $FEATURE != "" ]] ; then
    if [[ $(awk '$2 == "'$FEATURE'"' $ITESTS) == '' ]] ; then
        echo "ERROR: Feature $FEATURE not found in itests.include"
        cd
        rm -rf $TEMP
        exit 127
    fi
fi

declare -a GRADES
GRADES=("BASIC" "MIN" "INTER" "ADV")

BRDONE=$(git branch -r | awk '{print $1}' | cut -d'/' -f2 | grep -e BASIC -e MIN -e INTER -e ADV | grep -- "-PASS")
BRANCHES=""
for grade in "${GRADES[@]}" ; do
    # first, find all features for that grade
    features=$(grep $grade $ITESTS | awk '{print $2}' | uniq)
    for feature in $features ; do
        branch=$grade-$feature
        if [[ "$BRANCHES" != *"$branch"* ]] ; then
            BRANCHES="$BRANCHES $branch"
        fi
    done
done

REPORT=""
BFAIL=""
PREREQ=""
GRADE="F"
build_report $BRDONE
eval_grade

if [[ $1 == "status" ]] ; then
    print_report "$REPORT" "$GRADE"
    cd
    rm -rf $TEMP
    exit 0
fi

if [[ "$BRDONE" == *"-$FEATURE-PASS"* ]] ; then
    echo "ERROR: You are already passing $FEATURE"
    echo "----------------------------------------"
    print_report "$REPORT" "$GRADE"
    cd
    rm -rf $TEMP
    exit 0
fi

# PREREQ contains the BASIC and MIN prerequisites that must be passed first
# Once all of those are passed, INTER and ADV do not require a specific order

if [[ $PREREQ != "" && $PREREQ != *"-$FEATURE"* ]] ; then
    echo "ERROR: You must pass prerequisite feature tests:"
        for pre in $PREREQ ; do
        echo "  $pre"
    done
    echo "----------------------------------------"
    print_report "$REPORT" "$GRADE"
    cd
    rm -rf $TEMP
    exit 1
fi

# Must convert feature to tests...
LINES=$(awk '$2 == "'$FEATURE'"' $ITESTS)
TESTS=""
while IFS= read -r line || [[ -n "$line" ]] ; do
    test=$(echo $line | awk '$2 == "'$1'"' | awk '{print $3}')
    TESTS="$TESTS $test"
done <<< "$LINES"

./integration.sh $TESTS

FAIL=$?

if [[ $FAIL != 0 ]] ; then
    echo "ERROR: Failed one or more test cases"
    echo "ERROR: Recorded grade remains $GRADE"
    cd
    rm -rf $TEMP
    exit 1
fi

LEVEL=$(awk '$2 == "'$FEATURE'"' $ITESTS | awk '{print $1}' | uniq)
FEATLEV="${LEVEL}-${FEATURE}"

echo "----------------------------------------"
echo "Updated project feature status:"
REPORT=""
BFAIL=""
build_report ${FEATLEV}-PASS $BRDONE
eval_grade
print_report "$REPORT" "$GRADE"

git checkout -b "${FEATLEV}-PASS" > git.log 2>&1
PASS=PASS.$LEVEL.$FEATURE
date > $PASS
git add $PASS >> git.log 2>&1
git commit -m "Automated grade: passed ${LEVEL} ${FEATURE}" >> git.log 2>&1
git push --set-upstream origin "${FEATLEV}-PASS" >> git.log 2>&1

if [[ $? == 0 ]] ; then
    cd /
    rm -rf $TEMP
    exit 0
fi

echo "ERROR: Could not create and push the grading results"
echo "ERROR: Please contact instructor with the following information"
echo ""
echo "temp = ${TEMP}"
echo "repository = ${REPOS}"
echo "branch = ${BRANCH}-${NEWGRADE}"
echo "pass = ${PASS}"
echo "git log is as follows"
cat git.log
echo "----------------------------------------"
