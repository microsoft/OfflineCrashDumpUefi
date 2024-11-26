#
# This script should be sourced from repo root, not executed.
# Run: . usetup.sh
# Not: ./usetup.sh`
#

if [ ! -f "./usetup.sh" ]
then
        echo This file should be sourced from the repo root, ". usetup.sh".
        return 1
fi

if [ ! -f "edk2/edksetup.sh" ]
then
        echo git submodules not updated in ROOT.
        echo In ROOT and in ROOT/edk2, run: git submodule update --init
        return 1
fi

if [ ! -f "edk2/BaseTools/Source/C/BrotliCompress/brotli/c/common/constants.h" ]
then
        echo git submodules not updated in EDK2.
        echo In ROOT/edk2, run: git submodule update --init
        return 1
fi

export GCC_AARCH64_PREFIX=aarch64-linux-gnu-
export WORKSPACE=$PWD/workspace
export PACKAGES_PATH=$PWD/edk2:$PWD
mkdir -v -p "$WORKSPACE/Conf"

pushd edk2
. edksetup.sh $*
popd

return 0
