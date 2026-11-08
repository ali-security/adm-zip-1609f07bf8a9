"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid unless `crc` is given) payload.
// The default crc of 0 is deliberately wrong: alloc used to happen before the
// crc check.
function craftBomb(declaredSize, method, content, crc = 0) {
    const name = Buffer.from("a");
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });
});

// The RSS checks above depend on how the OS commits lazily zero-filled pages, so
// the declared-size allocation is also asserted directly for every public reader
// listed in the advisory. Buffer.alloc / Buffer.allocUnsafe are wrapped while
// adm-zip reads the entry: the largest request is recorded and anything above
// ALLOC_LIMIT is refused, so a regression fails fast instead of committing
// gigabytes. The bombs carry a valid crc, so a fixed reader returns the real
// (tiny) content.
describe("decompression bomb (declared size) - CVE-2026-39244 public readers", () => {
    const zlib = require("zlib");
    const fs = require("fs");
    const os = require("os");
    const pth = require("path");
    const rimraf = require("rimraf");
    const crc32 = require("../util").crc32;

    const DECLARED = 0xffffffff; // ~4 GB, the largest size a classic zip header can declare
    const ALLOC_LIMIT = 64 * 1024 * 1024;
    const text = Buffer.from("hello");
    const bombs = {
        STORED: () => new Zip(craftBomb(DECLARED, 0 /* STORED */, text, crc32(text))),
        DEFLATED: () => new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, zlib.deflateRawSync(text), crc32(text)))
    };

    // runs fn with Buffer allocations guarded and returns the largest size requested
    function largestAllocation(fn) {
        const alloc = Buffer.alloc;
        const allocUnsafe = Buffer.allocUnsafe;
        let largest = 0;
        const guard = (orig) =>
            function (size) {
                if (size > largest) largest = size;
                if (size > ALLOC_LIMIT) {
                    throw new RangeError("refusing to allocate " + size + " bytes (declared entry size)");
                }
                return orig.apply(this, arguments);
            };
        Buffer.alloc = guard(alloc);
        Buffer.allocUnsafe = guard(allocUnsafe);
        try {
            fn();
        } finally {
            Buffer.alloc = alloc;
            Buffer.allocUnsafe = allocUnsafe;
        }
        return largest;
    }

    const tmpTarget = (tag) => pth.join(os.tmpdir(), "adm-zip-cve-2026-39244-" + tag + "-" + process.pid);

    Object.keys(bombs).forEach((method) => {
        const bomb = bombs[method];

        describe(method + " entry declaring ~4 GB", () => {
            it("getData returns the real data without allocating the declared size", () => {
                const entry = bomb().getEntries()[0];
                let data;
                expect(largestAllocation(() => (data = entry.getData()))).to.be.below(ALLOC_LIMIT);
                expect(data.equals(text)).to.equal(true);
            });

            it("readFile returns the real data without allocating the declared size", () => {
                const zip = bomb();
                let data;
                expect(largestAllocation(() => (data = zip.readFile("a")))).to.be.below(ALLOC_LIMIT);
                expect(data.equals(text)).to.equal(true);
            });

            it("readAsText returns the real data without allocating the declared size", () => {
                const zip = bomb();
                let data;
                expect(largestAllocation(() => (data = zip.readAsText("a")))).to.be.below(ALLOC_LIMIT);
                expect(data).to.equal("hello");
            });

            it("test() passes without allocating the declared size", () => {
                const zip = bomb();
                let ok;
                expect(largestAllocation(() => (ok = zip.test()))).to.be.below(ALLOC_LIMIT);
                expect(ok).to.equal(true);
            });

            it("extractEntryTo writes the real data without allocating the declared size", () => {
                const zip = bomb();
                const target = tmpTarget("entry-" + method);
                try {
                    expect(largestAllocation(() => zip.extractEntryTo("a", target, false, true))).to.be.below(ALLOC_LIMIT);
                    expect(fs.readFileSync(pth.join(target, "a")).equals(text)).to.equal(true);
                } finally {
                    rimraf.sync(target);
                }
            });

            it("extractAllTo writes the real data without allocating the declared size", () => {
                const zip = bomb();
                const target = tmpTarget("all-" + method);
                try {
                    expect(largestAllocation(() => zip.extractAllTo(target, true))).to.be.below(ALLOC_LIMIT);
                    expect(fs.readFileSync(pth.join(target, "a")).equals(text)).to.equal(true);
                } finally {
                    rimraf.sync(target);
                }
            });

            it("getDataAsync returns the real data without allocating the declared size", (done) => {
                const entry = bomb().getEntries()[0];
                const largest = largestAllocation(() =>
                    entry.getDataAsync((data, err) => {
                        try {
                            expect(err).to.equal(undefined);
                            expect(data.equals(text)).to.equal(true);
                            done();
                        } catch (e) {
                            done(e);
                        }
                    })
                );
                expect(largest).to.be.below(ALLOC_LIMIT);
            });

            it("readAsTextAsync returns the real data without allocating the declared size", (done) => {
                const zip = bomb();
                const largest = largestAllocation(() =>
                    zip.readAsTextAsync("a", (data, err) => {
                        try {
                            expect(err).to.equal(undefined);
                            expect(data).to.equal("hello");
                            done();
                        } catch (e) {
                            done(e);
                        }
                    })
                );
                expect(largest).to.be.below(ALLOC_LIMIT);
            });

            it("extractAllToAsync writes the real data without allocating the declared size", (done) => {
                const zip = bomb();
                const target = tmpTarget("async-" + method);
                const largest = largestAllocation(() =>
                    zip.extractAllToAsync(target, true, false, (err) => {
                        try {
                            expect(err).to.equal(undefined);
                            expect(fs.readFileSync(pth.join(target, "a")).equals(text)).to.equal(true);
                            done();
                        } catch (e) {
                            done(e);
                        } finally {
                            rimraf.sync(target);
                        }
                    })
                );
                expect(largest).to.be.below(ALLOC_LIMIT);
            });
        });
    });
});
