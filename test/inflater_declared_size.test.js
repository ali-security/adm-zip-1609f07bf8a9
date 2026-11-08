"use strict";

const { expect } = require("chai");
const zlib = require("zlib");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Inflater = require("../methods").Inflater;
const crc32 = require("../util").crc32;

// Regression test for CVE-2026-92000 (GHSA-rcw4-f5rp-g42v):
// The inflater capped output at the entry's declared uncompressed size only when
// that size was > 0, so a crafted archive declaring a size of 0 (with a valid
// crc) disabled the cap altogether and a tiny DEFLATE stream was inflated
// without limit. The cap was also enforced only through zlib's maxOutputLength,
// which the streaming API (used by getDataAsync and the other *Async readers)
// ignores, so the async path decompressed without limit whatever the declared
// size. The bombs below carry a valid crc so the only thing stopping them is the
// cap.

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

// Build a single-entry zip named "a" that declares `declaredSize` uncompressed
// bytes in both the local and the central header while carrying `content` as
// its (compressed) payload with the given crc.
function craftZip(declaredSize, method, content, crc) {
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

describe("decompression bomb (declared size 0 / async inflate) - CVE-2026-92000", () => {
    const nodeMajor = +process.versions.node.split(".")[0];
    // the sync cap relies on zlib's maxOutputLength, which adm-zip passes on Node >= 15
    const syncCapped = nodeMajor >= 15;

    const payload = Buffer.alloc(1024 * 1024, 0x41); // 1 MB of real output
    const deflated = zlib.deflateRawSync(payload); // ~1 KB on the wire
    const payloadCrc = crc32(payload);
    const bomb = (declared) => new Zip(craftZip(declared, 8 /* DEFLATED */, deflated, payloadCrc));

    // asserts the async read failed on the size cap and returned no data
    const expectCapped = (done) => (data, err) => {
        try {
            expect(err, "async inflate must enforce the declared size").to.be.an("error");
            expect(err.message).to.match(/exceeds the declared uncompressed size/);
            expect(data.length).to.equal(0);
            done();
        } catch (e) {
            done(e);
        }
    };

    it("sanity: the crafted archive is a valid entry with an honest declared size", (done) => {
        const honest = bomb(payload.length);
        expect(honest.getEntries()[0].getData().equals(payload)).to.equal(true);
        honest.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(payload)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("Inflater.inflate does not treat a declared size of 0 as unlimited", function () {
        if (!syncCapped) this.skip();
        expect(() => new Inflater(deflated, 0).inflate()).to.throw(RangeError);
    });

    it("Inflater.inflateAsync does not treat a declared size of 0 as unlimited", (done) => {
        new Inflater(deflated, 0).inflateAsync(expectCapped(done));
    });

    it("Inflater.inflateAsync stops at a non-zero declared size", (done) => {
        new Inflater(deflated, 10).inflateAsync(expectCapped(done));
    });

    it("getData does not treat a declared size of 0 as unlimited", function () {
        if (!syncCapped) this.skip();
        expect(() => bomb(0).getEntries()[0].getData()).to.throw(RangeError);
    });

    it("readFile does not treat a declared size of 0 as unlimited", function () {
        if (!syncCapped) this.skip();
        expect(() => bomb(0).readFile("a")).to.throw(RangeError);
    });

    it("readAsText does not treat a declared size of 0 as unlimited", function () {
        if (!syncCapped) this.skip();
        expect(() => bomb(0).readAsText("a")).to.throw(RangeError);
    });

    it("extractAllTo does not inflate an entry declaring size 0 without limit", function () {
        if (!syncCapped) this.skip();
        const target = pth.join(os.tmpdir(), "adm-zip-cve-2026-92000-sync-" + process.pid);
        try {
            expect(() => bomb(0).extractAllTo(target, true)).to.throw(RangeError);
            expect(fs.existsSync(pth.join(target, "a"))).to.equal(false);
        } finally {
            rimraf.sync(target);
        }
    });

    it("getDataAsync does not treat a declared size of 0 as unlimited", (done) => {
        bomb(0).getEntries()[0].getDataAsync(expectCapped(done));
    });

    it("getDataAsync stops at the declared size instead of inflating without limit", (done) => {
        bomb(10).getEntries()[0].getDataAsync(expectCapped(done));
    });

    it("readFileAsync reports the size cap error to the caller", (done) => {
        bomb(0).readFileAsync("a", expectCapped(done));
    });

    it("readAsTextAsync reports the size cap error to the caller", (done) => {
        bomb(0).readAsTextAsync("a", expectCapped(done));
    });

    it("extractAllToAsync fails on the size cap instead of writing the inflated bomb", (done) => {
        const target = pth.join(os.tmpdir(), "adm-zip-cve-2026-92000-async-" + process.pid);
        bomb(0).extractAllToAsync(target, true, false, (err) => {
            try {
                expect(err, "extractAllToAsync must enforce the declared size").to.be.an("error");
                expect(err.message).to.match(/exceeds the declared uncompressed size/);
                expect(fs.existsSync(pth.join(target, "a"))).to.equal(false);
                done();
            } catch (e) {
                done(e);
            } finally {
                rimraf.sync(target);
            }
        });
    });

    it("getDataAsync reports a malformed deflate stream instead of crashing", (done) => {
        // 0xff starts a final block of the reserved type 3 -> Z_DATA_ERROR
        const zip = new Zip(craftZip(10, 8 /* DEFLATED */, Buffer.from([0xff, 0xff, 0xff, 0xff]), 0));
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.be.an("error");
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a genuinely empty DEFLATED entry declaring size 0", (done) => {
        const zip = new Zip(craftZip(0, 8 /* DEFLATED */, zlib.deflateRawSync(Buffer.alloc(0)), 0));
        expect(zip.getEntries()[0].getData().length).to.equal(0);
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("still reads a legitimate DEFLATED entry synchronously and asynchronously", (done) => {
        const zip = new Zip();
        const text = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", text);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(text)).to.equal(true);
        round.readFileAsync("d.txt", (data, err) => {
            try {
                expect(err).to.equal(undefined);
                expect(data.equals(text)).to.equal(true);
                done();
            } catch (e) {
                done(e);
            }
        });
    });
});
