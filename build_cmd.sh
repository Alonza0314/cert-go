#! /bin/bash

usage() {
	echo "Usage: $0 [linux_amd64|mac_arm64]"
	exit 1
}

make_main() {
    mkdir -p ./main
    touch ./main/main.go

    echo "package main" > ./main/main.go
    echo "import \"github.com/Alonza0314/cert-go/cmd\"" >> ./main/main.go
    echo "func main() {" >> ./main/main.go
    echo "	cmd.Execute()" >> ./main/main.go
    echo "}" >> ./main/main.go
}

remove_main() {
	rm -rf ./main
}

main() {
	if [ $# -ne 1 ]; then
		usage
	fi

	case "$1" in
		linux_amd64)
			make_main
			GOOS=linux GOARCH=amd64 go build -o ./build/cert-go ./main/main.go
			remove_main
			;;
		mac_arm64)
			make_main
			GOOS=darwin GOARCH=arm64 go build -o ./build/cert-go ./main/main.go
			remove_main
			;;
		*)
			usage
			;;
	esac
}

main "$@"