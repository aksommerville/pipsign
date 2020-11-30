#!/bin/sh

usage() {
  echo ""
  echo "Usage: $0 INPUT [OUTPUT]"
  echo ""
  echo "With INPUT only, read and validate this disc image."
  echo ""
  echo "With INPUT and OUTPUT:"
  echo "  INPUT may be a directory or an HFS image."
  echo "  If directory, we will use hfsutils (from Retro68) to generate an image first."
  echo "  If regular file, we will copy to OUTPUT and sign it."
  echo ""
}

guess_size() {
  #TODO Might need to bump this to minimum 64. Not sure of that yet tho.
  echo $(($( du -sm "$INPATH" | cut -f1 ) + 2))
}

deep_copy_hfs() {
  find "$INPATH" -mindepth 1 -type d | while read D ; do
    DSTPATH="$(echo "$D" | sed 's,^'"$INPATH"',,' | tr '/' ':')"
    hmkdir "$DSTPATH" || exit 1
  done
  find "$INPATH" -type f | while read F ; do
    DSTPATH="$(echo "$F" | sed 's,^'"$INPATH"',,;s/\.hqx$//;s/\.bin$//' | tr '/' ':')"
    echo "  $F => $DSTPATH"
    hcopy "$F" "$DSTPATH" || exit 1
  done
}

if [ "$#" -lt 1 ] || [ "$#" -gt 2 ] ; then
  usage
  exit 1
fi

INPATH="$1"
OUTPATH="$2"

# No OUTPATH means we are only validating INPATH.
if [ -z "$OUTPATH" ] ; then
  src/check.py "$INPATH"
  exit $?
fi

# INPATH directory, generate the HFS image.
if [ -d "$INPATH" ] ; then
  SIZE="$(guess_size)"
  echo "Generating blank $SIZE MB image '$OUTPATH'..."
  dd if=/dev/zero of="$OUTPATH" bs=$((1024*1024)) count=$SIZE || exit 1
  echo "Formatting..."
  hformat -l "$(basename $INPATH)" "$OUTPATH" || exit 1
  echo "Copying boot block..."
  dd if=src/bootblock of="$OUTPATH" bs=1024 count=1 conv=notrunc || exit 1
  echo "Mounting..."
  hmount "$OUTPATH" || exit 1
  echo "Copying files into HFS image..."
  deep_copy_hfs || exit 1
  echo "Bless System Folder..."
  hattrib -b "System Folder" || exit 1
  echo "Unmounting..."
  humount "$OUTPATH" || exit 1
else # INPATH regular file, just copy to OUTPATH
  cp "$INPATH" "$OUTPATH" || exit 1
fi

# ...and sign it
src/sign.py "$OUTPATH" || exit 1
echo "$OUTPATH: Generated HFS image from '$INPATH'"

exit 0
#--- XXX ----------------- older script, rekajiggering the interface a bit ------------------

RETRO68BIN=

#----------------------------------------------------------------------

usage() {
  echo ""
  echo "Usage: $0 COMMAND ..."
  echo ""
  echo "COMMAND:"
  echo ""
  echo "  mkfs                Generate an HFS image from directory."
  echo "    --in=PATH         Input directory, will be root of HFS volume."
  echo "    --out=PATH        Output image, will clobber."
  echo "    --sign            Generate PippinAuthenticationFile and sign it."
  echo "    --toolchain=PATH  Location of Retro68's 'toolchain' directory."
  echo "    --size=INTEGER    Size of image in MB (omit to guess)."
  echo ""
  echo "  check               Read an HFS image and validate its PippinAuthenticationFile."
  echo "    --in=PATH         HFS image. Read only."
  echo ""
  echo "  sign                Locate PippinAuthenticationFile and rewrite it."
  echo "    --image=PATH      HFS image (read/write)."
  echo "    --p=INTEGER       Offset to PippinAuthenticationFile (omit to search)."
  echo ""
  echo "'mkfs' requires Retro68: https://github.com/autc04/Retro68"
  echo "'mkfs' automatically converts files named '*.txt', '*.bin', or '*.hqx'."
  echo "Anything else is copied verbatim, as a data fork."
  echo ""
}

if [ "$#" -lt 1 ] ; then
  usage
  exit 1
fi

COMMAND="$1"
shift 1

IN=
OUT=
SIGN=
IMAGE=
P=
TOOLCHAIN=
SIZE=

while [ "$#" -ge 1 ] ; do
  ARG="$1"
  shift 1
  KEY="$(echo "$ARG" | sed -En 's/^--([^=]*).*$/\1/p')"
  if [ -z "$KEY" ] ; then
    echo "Malformed argument: '$ARG'"
    usage
    exit 1
  fi
  VALUE="$(echo "$ARG" | sed -En 's/^--[^=]*=(.*)$/\1/p')"
  case "$KEY" in
  
    in) IN="$VALUE" ;;
    out) OUT="$VALUE" ;;
    sign) SIGN=1 ;;
    image) IMAGE="$VALUE" ;;
    p) P="$VALUE" ;;
    toolchain) TOOLCHAIN="$VALUE" ;;
    size) SIZE="$VALUE" ;;
    
    *)
      echo "Unknown option '$KEY'"
      usage
      exit 1
    ;;
  esac
done

#-------------------------------------------------------------

require_arg() {
  if [ -z "$1" ] ; then
    echo "Missing required argument '--$2'"
    exit 1
  fi
}

guess_size() {
  echo $(($( du -sm "$IN" | cut -f1 ) + 2))
}

deep_copy_hfs() {
  find "$IN" -mindepth 1 -type d | while read D ; do
    DSTPATH="$(echo "$D" | sed 's,^'"$IN"',,' | tr '/' ':')"
    hmkdir "$DSTPATH" || exit 1
  done
  find "$IN" -type f | while read F ; do
    DSTPATH="$(echo "$F" | sed 's,^'"$IN"',,;s/\.hqx$//;s/\.bin$//' | tr '/' ':')"
    echo "  $F => $DSTPATH"
    hcopy "$F" "$DSTPATH" || exit 1
  done
}

#-------------------------------------------------------------

case "$COMMAND" in

  mkfs)
    require_arg "$IN" in
    require_arg "$OUT" out
    if [ ! -d "$IN" ] ; then
      echo "$IN: Must be a directory"
      exit 1
    fi
    if [ -z "$TOOLCHAIN" ] ; then
      # If they got Retro68's executables on the PATH, that's cool.
      if ! ( which hformat >/dev/null ) ; then
        echo "Please provide '--toolchain=/path/to/Retro68-build/toolchain'"
        exit 1
      fi
    else
      TOOLCHAIN="$TOOLCHAIN/bin/"
    fi
    if [ -z "$SIZE" ] ; then
      SIZE="$(guess_size)"
    fi
    if [ "$SIZE" -gt 800 ] || [ "$SIZE" -lt 2 ] ; then
      echo "Improbable size '$SIZE'. Must be in 2..800."
      exit 1
    fi
    
    echo "Generating blank image '$OUT'..."
    dd if=/dev/zero of="$OUT" bs=$((1024*1024)) count=$SIZE || exit 1
    echo "Formatting..."
    ${TOOLCHAIN}hformat -l "$(basename $IN)" "$OUT" || exit 1
    echo "Copying boot block..."
    dd if=src/bootblock of="$OUT" bs=1024 count=1 conv=notrunc || exit 1
    echo "Mounting..."
    ${TOOLCHAIN}hmount "$OUT" || exit 1
    echo "Copying files into HFS image..."
    deep_copy_hfs || exit 1
    # "Bless" the System Folder. I don't know what this means, but it seems important.
    ${TOOLCHAIN}hattrib -b "System Folder" || exit 1
    echo "Unmounting..."
    ${TOOLCHAIN}humount "$OUT" || exit 1
    if [ -n "$SIGN" ] ; then
      src/sign.py "$OUT" || exit 1
    fi
    echo "$OUT: Generated HFS image from '$IN'"
  ;;
  
  check)
    require_arg "$IN" in
    src/check.py "$IN" || exit 1
  ;;
  
  sign)
    echo "TODO: sign"
  ;;
  
  *)
    echo "Unknown command '$COMMAND'"
    usage
    exit 1
  ;;
esac
