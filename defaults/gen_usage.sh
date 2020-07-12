#!/bin/bash

rm ./USAGE.md
echo "$(
  for f in ./main/main.yml; do
    echo "Usage files printed **bold** might benefit from a config interface"
    echo
    echo "### \`$f\`"
    echo
    for p in $(yq r $f --printMode p "*" | sort); do
        echo "#### \`$p\`:"
        for r in $(cd .. && rg -l "\{.* $p .*\}" | sort); do
            if [[ $r == *".yml" ]]; then
                echo "  - used in _\`$r\`_"
            else
                echo "  - used in **\`$r\`**"
            fi
        done
    done
  done
)" > ./USAGE.md
