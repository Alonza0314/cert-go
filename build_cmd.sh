#! /bin/bash

mkdir -p ./main
touch ./main/main.go

echo "package main" > ./main/main.go
echo "import \"github.com/Alonza0314/cert-go/cmd\"" >> ./main/main.go
echo "func main() {" >> ./main/main.go
echo "	cmd.Execute()" >> ./main/main.go
echo "}" >> ./main/main.go

go build -o ./build/cert-go ./main/main.go

rm -rf ./main