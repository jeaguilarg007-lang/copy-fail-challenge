REPORT: CVE-2026-31431 — Copy Fail

Technical summary (in my own words):

CVE-2026-31431, also called "Copy Fail," is a logic bug in the Linux kernel
cryptography subsystem. It allowed an attacker to write controlled data into
pages that belong to the page cache of a setuid file, without changing the file
on disk.

The root cause was a 2017 optimization in `crypto/algif_aead.c` that tried to
perform AEAD operations in-place for better performance. To do this, the code
reused the same scatterlist for both `src` and `dst` in the cipher request
(`req->src = req->dst`). That meant, when input pages came from `splice()` and
and lived in the page cache, the kernel could end up using page cache pages as
the destination buffer for the crypto operation.

This is dangerous because the authentication/decryption step writes beyond the
expected output region (for example, `dst[assoclen + cryptlen]`). If `dst`
shares pages with page cache memory, those writes can corrupt memory used by
other files. The exploit takes advantage of this by planting 4 bytes in the
page cache that later affect the behavior of a loaded setuid binary like
`/usr/bin/su`. That gives root without ever modifying the file’s inode or
persisted disk content — which is why the attack is stealthy.

Course concepts connections:
- Page cache: the bug depends on the page cache holding file data in memory,
  and on `splice()` causing those pages to be reused in kernel crypto paths.
- setuid: a setuid binary like `su` can be abused if its in-memory image is
  corrupted, even though the file on disk looks normal.
- Inodes and permissions: the exploit does not need to change the inode or file
  permissions; it works by changing the loaded memory image instead.

Lessons learned:
- Performance optimizations can create security bugs if they assume the same
  invariants hold in every I/O path. In this case, in-place crypto broke when
  the input came from page cache pages.
- Security review must consider subsystem interactions, not just the single
  function being changed. Here, the bug is about how AF_ALG, `splice()`, and the
  page cache work together.
- Temporary mitigations like disabling a vulnerable module are useful while a
  proper patch is developed.

What I did in this exercise:
- Set up the vulnerable VM and attempted the public PoC, documenting the output.
- Applied and verified a patch in `crypto/algif_aead.c`, rebuilt the kernel,
  and created the required evidence files.

(End of report)
