# gazelle
Gazelle MPC Framework

## Install

This was last tested on Ubuntu 16.04 LTS and 17.10
```bash
  # Install dependencies
  sudo apt-get install g++ nasm cmake libboost-all-dev
  
  # Clone this repo
  git clone https://github.com/chiraag/gazelle_mpc
  cd gazelle_mpc
  git submodule update --init --recursive
  
  # Compile miracl for OSU cryptotools
  cd third_party/cryptoTools/thirdparty/linux
  bash miracl.get
  cd miracl/miracl/source
  sed -i -e 's/g++ -c/g++ -c -fPIC/g' linux64
  bash linux64
  
  # Compile cryptotools
  cd ../../../../../
  cmake .
  make -j8
  
  # Compile gazelle
  cd ../../
  make -j8
```

If you want to run to run the network conversion scripts you will 
need a python interpreter and pytorch. These scripts were tested with
Anaconda3 on a machine that had a GPU.

## Running examples

Have a look at the demo folder to see some examples.
