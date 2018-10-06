### Step 1:
Create 4 note to alloced 4 new memory chunk (1 -> 4).

### Step 2:
Choice back three time to chunk 1 and edit it to overwrite chunk size of chunk 2.

After:
```
chunk_2: -> |0x3F1   |
            |chunk 1 |
            |chunk 3 |
            |message |
            |...     |
```
Before
```
chunk_2: -> |0x7E1   |
            |chunk 1 |
            |chunk 3 |
            |message |
            |...     |
```
### Step 3:
Free chunk_2 to make unsotedbins with chunk size 0x7F0.

### Step 4:
Free chunk 3 to push it in tcache.
```
tcache -> |....    |
          |....    |
          |chunk_3 | -> 0
          |....    |
          |....    |
```

### Step 5:
Next to latest note.
Create BigNote to create new chunk start addr same chunk_2 and overlap chunk 3.
Overwirte `chunk_3->fd` to make fake chunk to GOT table.
```
tcache -> |....    |
          |....    |
          |chunk_3 | -> GOT
          |....    |
          |....    |
```

### Step 6:
Create new note to alloc new chunk = chunk_3
```
tcache -> |....    |
          |....    |
          |GOT     | -> ...
          |....    |
          |....    |
```

### Step 7:
Create new note alloc to GOT table.
Edit GOT to `canyourunme()` function.

See my solution in: [solve.py](solve.py)
