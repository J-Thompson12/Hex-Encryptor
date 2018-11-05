#!/bin/bash

# Get the origin root (e.g. git@gitlab.mx.com:mx)
origin=$(git remote get-url origin | sed "s/\(.*\)\/.*/\1/")

repos=("clibs" "mmx-common")

cd ..;
for r in "${repos[@]}"; do
  echo -e "CLONE: $r";
  git clone "$origin/$r.git";
done
