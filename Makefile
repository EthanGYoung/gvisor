release = $(shell lsb_release -cs)

all:
	make docker custom_gv_deps

run:
	sudo rm -rf /tmp/runsc
	sudo docker run --runtime=runsc cfs-boot python /usr/src/python_trace/trace_layer.py $(FILE)

build:
	sudo rm -rf /tmp/runsc
	bazel build runsc
	sudo cp ./bazel-bin/runsc/linux_amd64_pure_stripped/runsc /usr/local/bin

build_debug:
	sudo rm -rf /tmp/runsc
	bazel build -c dbg runsc
	sudo cp ./bazel-bin/runsc/linux_amd64_pure_debug/runsc /usr/local/bin
	

docker:
	sudo apt-get update
	sudo apt-get -y install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
	curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
	sudo apt-key fingerprint 0EBFCD88
	sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(release) stable"
	sudo apt-get update
	sudo apt-get -y install docker-ce
	#sudo apt-get -y install docker-ce=5:19.03.2~3-0~ubuntu-xenial

custom_gv_deps:
	sudo apt-get install pkg-config zip g++ zlib1g-dev unzip python
	sudo wget https://github.com/bazelbuild/bazel/releases/download/0.25.2/bazel-0.25.2-installer-linux-x86_64.sh
	sudo chmod +x bazel-0.25.2-installer-linux-x86_64.sh
	./bazel-0.25.2-installer-linux-x86_64.sh --user
	rm -f bazel-0.25.2-installer-linux-x86_64.sh	
