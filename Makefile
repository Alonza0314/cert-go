.PHONY: all linux_amd64 mac_arm64

all: linux_amd64 mac_arm64

linux_amd64:
	./build_cmd.sh linux_amd64

mac_arm64:
	./build_cmd.sh mac_arm64
