#!/bin/bash

# directory of the test script, i.e. the test directory
DIR=$(dirname "$(readlink -f "$0")")
APP="../TrezorPass.py"
PWDB="tcase.pwdb" # pwdb password database
PASSPHRASE="test"
OPT=" -t -l 3 -n -f $PWDB -p $PASSPHRASE "  # base options
LOG=tcase.log
CSV=tcase.csv

green=`tput setaf 2`
red=$(tput setaf 1) # Error
reset=`tput sgr0`

GENGOLD=0 # 1...generate golden output, 0..do comparison runs
TESTPY2=1 # 1...test Python2 if installed, 0...don't test Python2
TESTPY3=1 # 1...test Python3 if installed, 0...don't test Python3

# outputs to stdout the --help usage message.
usage () {
  echo "${0##*/}: Usage: ${0##*/} [--help] [<testcasenumber> ...]"
  echo "${0##*/}: e.g. ${0##*/} 1 # run test case 1"
  echo "${0##*/}: e.g. ${0##*/} 1 2 3 # run test case 1, 2 and 3"
  echo "${0##*/}: e.g. ${0##*/} # no input will run all test cases"
}

if [ $# -eq 1 ]; then
  case "${1,,}" in
    --help | --hel | --he | --h | -help | -h | -v | --v | --version)
  	usage; exit 0 ;;
  esac
fi

function headerTrezorPassTestCase () {
    echo "Testing: Running $1 in $($py -V 2>&1)"
    #rm -f $PWDB $LOG $CSV
}

function trailerTrezorPassTestCase () {
    # generate golden results
    if [ $GENGOLD -eq 1 ]; then
        # echo "Generating golden results."
        for tfile in $LOG $CSV; do
            cp $tfile $1.$tfile
        done
    fi
    # comparison
    # no diff on pwdb files, they will always differ, even in size!
    for tfile in $LOG $CSV; do
        diff $tfile $1.$tfile
        if [ $? != 0 ]; then
            echo "${red}$1 failed in $tfile diff${reset}"
        fi
    done
    # cleanup
    rm -f $PWDB $LOG $CSV
}

function TrezorPassTestCase001 () {
    headerTrezorPassTestCase ${FUNCNAME[0]}
    $py $APP $OPT -f '' 2>> $LOG >> $LOG <<EOF
$PWDB
EOF
    $py $APP $OPT -y $CSV 2>> $LOG >> $LOG
    trailerTrezorPassTestCase ${FUNCNAME[0]}
}


function TrezorPassTestCase002 () {
    headerTrezorPassTestCase ${FUNCNAME[0]}
    $py $APP $OPT -f '' 2>> $LOG >> $LOG <<<$PWDB
    # sort because otherwise there is no guarantee that the order will be the same between versions
    $py $APP $OPT -x 2>> $LOG | sort >> $LOG
    $py $APP $OPT -e 2>> $LOG | sort >> $LOG
    $py $APP $OPT -a -g g1 -k k1 -w p1 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -x 2>> $LOG | sort >> $LOG
    $py $APP $OPT -e 2>> $LOG | sort >> $LOG
    $py $APP $OPT -b -g g1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k2 -w p2 -m c2 2>> $LOG >> $LOG
    $py $APP $OPT -x 2>> $LOG | sort >> $LOG
    $py $APP $OPT -e 2>> $LOG | sort >> $LOG
    $py $APP $OPT -b -g g1 2>> $LOG >> $LOG
    $py $APP $OPT -y $CSV 2>> $LOG >> $LOG
    trailerTrezorPassTestCase ${FUNCNAME[0]}
}



function TrezorPassTestCase003 () {
    headerTrezorPassTestCase ${FUNCNAME[0]}
    $py $APP $OPT -f '' 2>> $LOG >> $LOG <<<$PWDB
    $py $APP $OPT -x  2>> $LOG >> $LOG
    $py $APP $OPT -e  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k1 -w p1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k1 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k1 -w p1 -m c1  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k1 -w p1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k1 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k1 -w p1 -m c1  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k1 -w p1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k1 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k1 -w p1 -m c1  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k2 -w p1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k2 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g1 -k k2 -w p1 -m c1  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k2 -w p1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k2 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g2 -k k2 -w p1 -m c1  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k2 -w p1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k2 -m c1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g g3 -k k2 -w p1 -m c1  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g4ñẽë儿 -k k1ñẽë儿 -w p1ñẽë儿 -m c1ñẽë儿  2>> $LOG >> $LOG
    $py $APP $OPT -a -g g4ñẽë儿 -k k1ñẽë儿 -w p1ñẽë儿 -m 'c1ñẽë儿 line1
        line2
        line3
        line4' 2>> $LOG >> $LOG
    $py $APP $OPT -a -g "\"\\" -k "\"\\" -w "\"\\" -m "\"\\" 2>> $LOG >> $LOG
    $py $APP $OPT -a -g "\\\"" -k "\\\"" -w "\\\"" -m "\\\"" 2>> $LOG >> $LOG
    $py $APP $OPT -a -g "\\\\" -k "\\\\" -w "\\\\" -m "\\\\" 2>> $LOG >> $LOG
    $py $APP $OPT -a -g "\\\\\\" -k "\\\\\\" -w "\\\\\\" -m "\\\\\\" 2>> $LOG >> $LOG
    xsel -bc >> /dev/null 2>&1 ; echo "clip clear" 2>> $LOG >> $LOG
    $py $APP $OPT -c -g g3 -k k2 2>> $LOG >> $LOG
    xsel -bo 2>> $LOG >> $LOG ; echo "clip paste" 2>> $LOG >> $LOG #empty
    xsel -bc >> /dev/null 2>&1 ; echo "clip clear" 2>> $LOG >> $LOG
    $py $APP $OPT -c -g g4ñẽë儿 -k k1ñẽë儿 2>> $LOG >> $LOG
    xsel -bo 2>> $LOG >> $LOG ; echo "clip paste" 2>> $LOG >> $LOG
    $py $APP $OPT -s -g g3 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -s -g g3 2>> $LOG >> $LOG
    $py $APP $OPT -s -g g4ñẽë儿 -k k1ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -s -g g4ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -o -g g3 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -o -g g3 2>> $LOG >> $LOG
    $py $APP $OPT -o -g g4ñẽë儿 -k k1ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -o -g g4ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -b -g g3 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -b -g g3 2>> $LOG >> $LOG
    $py $APP $OPT -b -g g4ñẽë儿 -k k1ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -b -g g4ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -e -g g3 2>> $LOG >> $LOG
    $py $APP $OPT -e -g g4ñẽë儿 2>> $LOG >> $LOG
    $py $APP $OPT -e 2>> $LOG | sort >> $LOG
    $py $APP $OPT -x 2>> $LOG | sort >> $LOG
    $py $APP $OPT -a -g g1 -k k3 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -d -g g1 -k k3 2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg1 -k k1 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg1 -k k2 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg1 -k k3 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -d -g dg1 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -d -g dg1 2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg2 -k k1 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg2 -k k2 -w d3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg2 -k k2 -w u3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg2 -k k3 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg2 -k k2 -w d3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -a -g dg2 -k k4 -w p3 -m c3  2>> $LOG >> $LOG
    $py $APP $OPT -d -g dg2 -k k2 2>> $LOG >> $LOG <<<'Y
N
Y
'
    $py $APP $OPT -b -g dg2 -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -r -g dg2 -0 dg2new 2>> $LOG >> $LOG
    $py $APP $OPT -b -g dg2new -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -u -g dg2new -k k2 -2 pnew 2>> $LOG >> $LOG <<<'Y
N
Y
'
    $py $APP $OPT -u -g dg2new -k k2 -3 cnew 2>> $LOG >> $LOG <<<'Y
Y
N
'
    $py $APP $OPT -b -g dg2new -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -u -g dg2new -k k2 -1 kvnew -2 pvnew -3 pvnew 2>> $LOG >> $LOG <<<'N
Y
N
'
    $py $APP $OPT -b -g dg2new -k k2 2>> $LOG >> $LOG
    $py $APP $OPT -u -g dg2new -k k4 -1 k4vnew -2 p4vnew -3 p4vnew 2>> $LOG >> $LOG
    $py $APP $OPT -b -g dg2new -k k4 2>> $LOG >> $LOG
    $py $APP $OPT -y $CSV 2>> $LOG >> $LOG
    $py $APP $OPT -z $CSV 2>> $LOG >> $LOG
    $py $APP $OPT -y $CSV 2>> $LOG >> $LOG
    $py $APP $OPT -e 2>> $LOG | sort >> $LOG
    $py $APP $OPT -x 2>> $LOG | sort >> $LOG
    trailerTrezorPassTestCase ${FUNCNAME[0]}
}


# main
pushd $DIR > /dev/null
if [ $TESTPY2 -eq 1 ] && [ $(which python2) != "" ]; then pythonversions[2]=$(which python2); fi
if [ $TESTPY3 -eq 1 ] && [ $(which python3) != "" ]; then pythonversions[3]=$(which python3); fi
if [ $# -ge 1 ]; then
    for py in "${pythonversions[@]}"; do
        echo ""
        echo "Note   : Now performing tests with Python version $py"
        set -- "$@"
        for tcase in "$@"; do
            # is it really a valid number?
            re='^[0-9]+$'
            if ! [[ $tcase =~ $re ]] ; then
               echo "Error: $tcase is not a number. Skipping it." >&2
               continue
            fi
            fname=$(printf "TrezorPassTestCase%0*d" 3 $tcase)
            $fname
        done
        echo "End    : If no warnings or errors were echoed, then there were no errors, all tests terminated successfully."
    done
else
    # zero arguments, we run pall test cases
    echo "No argument was given. All testcases will be run. This might take up to 10 minutes."
    for py in "${pythonversions[@]}"; do
        echo ""
        echo "Note   : Now performing tests with Python version $py"
        # compgen -A function TrezorPassTestCase --> list of all functions starting with TrezorPassTestCase
        for fname in $(compgen -A function TrezorPassTestCase); do
            $fname
        done
        echo "End    : If no warnings or errors were echoed, then there were no errors, all tests terminated successfully."
    done
fi
echo
echo "Log files contain " $(grep -i error *$LOG | wc -l) " errors."
echo "Log files contain " $(grep -i critical *$LOG | wc -l) " critical issues."
echo "Log files contain " $(grep -i warning *$LOG | grep -v noconfirm | grep -v "If file exists it will be overwritten" | wc -l) " warnings."
echo "Log files contain " $(grep -i ascii *$LOG | wc -l) " ascii-vs-unicode issues."
echo "Log files contain " $(grep -i unicode *$LOG | wc -l) " unicode issues."
echo "Log files contain " $(grep -i latin *$LOG | wc -l) " latin-vs-unicode issues."
echo "Log files contain " $(grep -i byte *$LOG | wc -l) " byte-vs-unicode issues."
popd > /dev/null
exit 0
