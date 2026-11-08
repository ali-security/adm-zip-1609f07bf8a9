"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");

// Regression test for GHSA-p634-w6r4-rjp2:
// a ZIP archive can declare two entries with the identical name. adm-zip kept
// both in its entry list but only the last one in its name lookup table, so
// getEntry()/readFile() (table) and extractAllTo() (list) resolved the same
// name to different content. An application validating an entry's bytes via
// getEntry() before extracting could approve one file while another one landed
// on disk. Such archives must be rejected.

const DUPLICATE = /Duplicate entry name/;

// Build an archive whose entries carry the given (possibly duplicate) names.
// adm-zip will not write duplicate names itself, so the archive is written with
// unique placeholder names of the same byte length and the name bytes are then
// patched in both the local and the central directory headers.
function craftArchive(entries) {
    const writer = new Zip({ noSort: true });
    const placeholders = entries.map((e, i) => {
        const placeholder = String.fromCharCode(0x41 + i).repeat(Buffer.byteLength(e.name));
        writer.addFile(placeholder, Buffer.from(e.data));
        return placeholder;
    });
    const buf = Buffer.from(writer.toBuffer());
    placeholders.forEach((placeholder, i) => {
        const from = Buffer.from(placeholder);
        const to = Buffer.from(entries[i].name);
        let patched = 0;
        for (let at = buf.indexOf(from); at !== -1; at = buf.indexOf(from, at + from.length)) {
            to.copy(buf, at);
            patched++;
        }
        // local file header + central directory header
        expect(patched, "name occurrences of " + entries[i].name).to.equal(2);
    });
    return buf;
}

describe("GHSA-p634-w6r4-rjp2 - duplicate entry names", () => {
    const target = pth.join(os.tmpdir(), "adm-zip-ghsa-p634-w6r4-rjp2-" + process.pid);

    beforeEach(() => {
        rimraf.sync(target);
        fs.mkdirSync(target, { recursive: true });
    });
    afterEach(() => rimraf.sync(target));

    // The advisory's PoC: "a.txt" (FIRST) renamed to "b.txt" next to "b.txt" (SECOND).
    const poc = () =>
        craftArchive([
            { name: "b.txt", data: "FIRST" },
            { name: "b.txt", data: "SECOND" }
        ]);

    it("check-then-extract cannot approve one entry while extracting another", () => {
        const buf = poc();
        const zip = new Zip(buf);
        // the application inspects the named entry, then extracts the archive
        expect(() => {
            const approved = zip.readFile("b.txt");
            zip.extractAllTo(target);
            const written = fs.readFileSync(pth.join(target, "b.txt"));
            // vulnerable: approved "SECOND" while "FIRST" was written to disk
            expect(written.toString()).to.equal(approved.toString());
        }).to.throw(DUPLICATE);
        expect(fs.readdirSync(target)).to.deep.equal([]);
    });

    it("rejects the archive from every entry accessor", () => {
        const buf = poc();
        expect(() => new Zip(buf).getEntry("b.txt")).to.throw(DUPLICATE);
        expect(() => new Zip(buf).readFile("b.txt")).to.throw(DUPLICATE);
        expect(() => new Zip(buf).readAsText("b.txt")).to.throw(DUPLICATE);
        expect(() => new Zip(buf).getEntries()).to.throw(DUPLICATE);
        expect(() => new Zip(buf).extractEntryTo("b.txt", target, false, true)).to.throw(DUPLICATE);
        expect(() => new Zip(buf).extractAllTo(target, true)).to.throw(DUPLICATE);
        expect(() => new Zip(buf).toBuffer()).to.throw(DUPLICATE);
        expect(fs.readdirSync(target)).to.deep.equal([]);
    });

    it("rejects the archive at load time when readEntries is set", () => {
        expect(() => new Zip(poc(), { readEntries: true })).to.throw(DUPLICATE);
    });

    it("keeps rejecting after the first error was caught", () => {
        const zip = new Zip(poc());
        expect(() => zip.getEntries()).to.throw(DUPLICATE);
        // a swallowed error must not leave a half-read archive behind
        expect(() => zip.getEntry("b.txt")).to.throw(DUPLICATE);
        expect(() => zip.getEntries()).to.throw(DUPLICATE);
        expect(() => zip.extractAllTo(target, true)).to.throw(DUPLICATE);
        expect(fs.readdirSync(target)).to.deep.equal([]);
    });

    it("extractAllToAsync rejects and writes nothing", () => {
        return new Zip(poc()).extractAllToAsync(target, true).then(
            () => {
                throw new Error("extractAllToAsync accepted an archive with duplicate entry names");
            },
            (err) => {
                expect(err.message).to.match(DUPLICATE);
                expect(fs.readdirSync(target)).to.deep.equal([]);
            }
        );
    });

    it("rejects duplicates hidden behind a __proto__ entry name", () => {
        const buf = craftArchive([
            { name: "__proto__", data: "FIRST" },
            { name: "__proto__", data: "SECOND" }
        ]);
        expect(() => new Zip(buf).getEntries()).to.throw(DUPLICATE);
        expect(() => new Zip(buf).extractAllTo(target, true)).to.throw(DUPLICATE);
        expect(fs.readdirSync(target)).to.deep.equal([]);
    });

    it("does not mistake Object.prototype member names for duplicates", () => {
        const names = ["constructor", "toString", "__proto__", "hasOwnProperty"];
        const zip = new Zip(craftArchive(names.map((name) => ({ name, data: "data of " + name }))));
        expect(zip.getEntries().map((e) => e.entryName)).to.deep.equal(names);
        for (const name of names) {
            expect(zip.readAsText(name)).to.equal("data of " + name);
        }
    });

    it("accepts the same file name in different folders", () => {
        const writer = new Zip();
        writer.addFile("one/b.txt", Buffer.from("FIRST"));
        writer.addFile("two/b.txt", Buffer.from("SECOND"));
        const zip = new Zip(writer.toBuffer());
        expect(zip.readAsText("one/b.txt")).to.equal("FIRST");
        expect(zip.readAsText("two/b.txt")).to.equal("SECOND");
        zip.extractAllTo(target, true);
        expect(fs.readFileSync(pth.join(target, "one", "b.txt")).toString()).to.equal("FIRST");
        expect(fs.readFileSync(pth.join(target, "two", "b.txt")).toString()).to.equal("SECOND");
    });
});
