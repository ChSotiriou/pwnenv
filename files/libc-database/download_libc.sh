#!/bin/bash

cat urls.txt | while read -r url
do
    name=$(echo $url | rev | cut -d / -f1 | rev)
    name=$(echo $name | rev | cut -d . -f2- | rev)
    echo $name     
    mkdir $name
    wget $url -O ./$name/$name.deb -q
    ar x ./$name/$name.deb > /dev/null

    tar -C ./$name -xvf data.tar.xz ./lib > /dev/null
    mv ./$name/lib/* ./$name
    rm control* data* debian*
    rm ./$name/*.deb ./$name/lib -r
done;
