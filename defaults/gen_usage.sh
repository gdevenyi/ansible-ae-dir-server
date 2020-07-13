#!/bin/bash

rm ./USAGE_REPORT.md
echo "$(
  for f in ./main/main.yml; do
    echo
    echo "### \`$f\`"
    echo
    for p in $(yq r $f --printMode p "*" | sort); do
        echo "#### \`$p\`:"
        for r in $(cd .. && rg -l -g 'defaults/main/*.yml' "\{.* $p.*\}" | sort); do
            if [[ $r != "defaults/main/main.yml" ]]; then
                echo "  - variable interfaced in _\`$r\`_"
            elif [[ $r == "defaults/main/main.yml" ]]; then
                echo "  - self-referenced in _\`$r\`_"
            else
                echo "# AN ERROR OCCURRED"
            fi
        done
        for r in $(cd .. && rg -l -g '!defaults/**' " $p" | sort); do
            if [[ $r == *".yml" ]]; then
                echo "  - ansible usage in \`$r\`"
            else
                echo "  - direct template usage in **\`$r\`**"
            fi
        done
    done
  done
)" > ./USAGE_REPORT.md
