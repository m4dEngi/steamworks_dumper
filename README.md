# steamworks_dumper
Quick and dirty steamworks dumper. It was written as a little helper tool for tracking changes in private and public steamworks api.
The code is far from perfect and whole just begs for rewriting from scratch, but i'm still sharing for people who might find it useful.

**example output can be found [here](https://bitbucket.org/m4dengi/steamclient_tracker)**. Tracking both stable and beta steam clients.

## building
```
$ mkdir build
$ cd build
$ cmake ../
```

## usage
```
./swdumper <path_to_steamclient.dylib> <out_path>
```
  **output path must be a valid existing directory!**
  
