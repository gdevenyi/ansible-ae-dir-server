#!/bin/bash

rm ./USAGE.md
echo "$(
  for f in ./main/main.yml; do
    echo
    echo "### \`$f\`"
    echo
    for p in $(yq r $f --printMode p "*" | sort); do
        echo "#### \`$p\`:"
        for r in $(cd .. && rg -l "\{.* $p .*\}" | sort); do
            if [[ $r == "defaults/main/"*".yml" ]]; then
                echo "  - variable interfaced in _\`$r\`_"
            elif [[ $r == *".yml" ]]; then
                echo "  - ansible usage in \`$r\`"
            else
                echo "  - template usage in **\`$r\`**"
            fi
        done
    done
  done
)" > ./USAGE.md
