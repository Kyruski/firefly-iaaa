#!/bin/bash

export ff_addons='["iam_web.admin"]'
webpack-dev-server \
    --output-filename="[name].js" --output-library="[name]" --output-path="./dist" \
    -w --mode development \
    __target__/build.app.js \
    src/iam_web/styles.scss
