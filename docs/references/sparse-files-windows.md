# Reference: Sparse Files on Windows

Sources:
- https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-files
- https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_sparse
- https://learn.microsoft.com/en-us/windows/win32/api/winioctl/ni-winioctl-fsctl_set_zero_data

## What Windows requires for sparse files

1. **Mark the file as sparse**: Send `FSCTL_SET_SPARSE` via `DeviceIoControl`. This marks the file in the MFT (Master File Table) as capable of having sparse regions.
2. **Designate zero regions**: Send `FSCTL_SET_ZERO_DATA` with a `FILE_ZERO_DATA_INFORMATION` struct specifying the zero region's byte range. The NTFS driver then records these as holes without allocating disk clusters.

Without step 1, the file is treated as a regular (dense) file. Without step 2, any zeros written to disk are stored as actual data.

## What `set_len` (SetEndOfFile) does on Windows

`File::set_len(n)` calls `SetEndOfFile` on Windows. This:
- Extends the file to `n` bytes.
- Writes actual zeros to the new space (no sparse hole created).
- Does NOT set the sparse flag.
- Does NOT call `FSCTL_SET_ZERO_DATA`.

**Result**: On Windows, growing a container via `set_len` allocates real disk space for the zero-filled extension. This is a documented gap compared to Unix behaviour.

## What we do in Task 2

We do NOT implement sparse files on Windows. `set_len` creates a dense file with zeros. Behaviour is functionally correct (reads from unwritten regions return zeros), but not storage-efficient.

A future task could implement Windows sparse support using `DeviceIoControl` via the `windows-sys` crate. This is documented as a known gap.

## Reads from unwritten regions

Even on Windows without sparse files, reads from regions that were extended via `set_len` but never written to return zeros — the NTFS driver returns zero pages for these regions. The functional contract (zero-filled gaps) holds on all platforms.
