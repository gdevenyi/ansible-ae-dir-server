#!/bin/bash

SUFFIX=.USAGE_REPORT.md
cd ..
for f in defaults/main/*.yml; do
    rm $f$SUFFIX
    echo "$(
        for p in $(yq r $f --printMode p "*" | sort); do
            echo "#### \`$p\`:"
            for r in $(rg -l -g 'defaults/main/*.yml' "\{.* $p.*\}" | sort); do
                if [[ $r != "$f" ]]; then
                    echo "  - variable interfaced in _\`$r\`_"
                elif [[ $r == "$f" ]]; then
                    echo "  - self-referenced in _\`$r\`_"
                else
                    echo "# AN ERROR OCCURRED"
                fi
            done
            for r in $(rg -l -g '!defaults/**' " $p" | sort); do
                if [[ $r == *".yml" ]]; then
                    echo "  - ansible usage in \`$r\`"
                else
                    echo "  - direct template usage in **\`$r\`**"
                fi
            done
    done
    )" > $f$SUFFIX
done
cd defaults
