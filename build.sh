#!/bin/bash

gcc -shared -fPIC -o libintercept.so intercept.c -ldl
