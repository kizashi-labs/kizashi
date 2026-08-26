#!/bin/bash
# Run this from the server/ directory to install CLI dependencies
go get github.com/spf13/cobra@v1.8.1
go mod tidy
