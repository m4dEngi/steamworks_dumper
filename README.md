# steamworks_dumper
Quick and dirty steamworks dumper. It was written as a little helper tool for tracking changes in private steamworks api using 32bit linux client binaries.
The code is far from perfect and whole app just begs for rewriting from scratch, but i'm still sharing for people who might find it useful.

**example output can be found [here](https://github.com/SteamDatabase/SteamTracking/tree/master/Structs)**. Tracking both stable and beta steam clients.

## building
Get yourself a copy of capstone engine and just do 
```
$ mkdir build
$ cd build
$ cmake ../
```

## usage
```
./steamworks_dumper <path_to_steamclient.so> <out_path>
```
  **_output path must be a valid existing directory!_**
  
