"use strict";

const { expect } = require("chai");
const fs = require("fs");
const os = require("os");
const pth = require("path");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util/utils");

// Regression tests for CVE-2026-76845 (GHSA-vwc7-r8mq-g2x9):
// sanitize() only proves that the textual path of an entry stays below the
// extraction root. When a path component already exists on disk as a symlink
// (or a Windows junction) pointing outside the root, extractAllTo(),
// extractAllToAsync() and extractEntryTo() followed it and wrote, created or
// chmod-ed files outside the root - without any "../" in the archive.

const IN_THE_WAY = /There is a file in the way/;

// Create a link, skipping the test where the platform does not allow it
// (symlinks need a privilege or Developer Mode on Windows; junctions do not).
function makeLink(ctx, linkTarget, linkPath, type) {
    try {
        fs.symlinkSync(linkTarget, linkPath, type);
    } catch (e) {
        if (e.code === "EPERM" || e.code === "EACCES") ctx.skip();
        throw e;
    }
}

function archive(entries) {
    const zip = new Zip();
    for (const name of Object.keys(entries)) {
        zip.addFile(name, entries[name] === null ? Buffer.alloc(0) : Buffer.from(entries[name]));
    }
    return zip.toBuffer();
}

function expectRejected(promise, matcher) {
    return promise.then(
        () => {
            throw new Error("extractAllToAsync extracted through a symlink");
        },
        (err) => {
            expect(err).to.be.an("error");
            if (matcher) expect(err.message).to.match(matcher);
        }
    );
}

describe("CVE-2026-76845 - extraction must not follow symlinks inside the target", () => {
    const base = pth.join(os.tmpdir(), "adm-zip-cve-2026-76845-" + process.pid);
    const target = pth.join(base, "target");
    const outside = pth.join(base, "outside");
    const victim = pth.join(outside, "victim.txt");

    beforeEach(() => {
        rimraf.sync(base);
        fs.mkdirSync(target, { recursive: true });
        fs.mkdirSync(outside, { recursive: true });
        fs.writeFileSync(victim, "ORIGINAL");
    });
    afterEach(() => rimraf.sync(base));

    const outsideUntouched = () => {
        expect(fs.readFileSync(victim).toString()).to.equal("ORIGINAL");
        expect(fs.readdirSync(outside)).to.deep.equal(["victim.txt"]);
    };

    describe("extractAllTo", () => {
        it("does not overwrite a file outside the target through a file symlink", function () {
            makeLink(this, victim, pth.join(target, "victim.txt"), "file");
            const zip = new Zip(archive({ "victim.txt": "PWNED" }));
            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not create a file through a dangling symlink, even without overwrite", function () {
            makeLink(this, pth.join(outside, "created.txt"), pth.join(target, "created.txt"), "file");
            const zip = new Zip(archive({ "created.txt": "PWNED" }));
            expect(() => zip.extractAllTo(target, false)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not write a file through a symlinked directory", function () {
            makeLink(this, outside, pth.join(target, "link"), "junction");
            const zip = new Zip(archive({ "link/payload.txt": "PWNED", "link/victim.txt": "PWNED" }));
            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not create directories through a symlinked directory", function () {
            makeLink(this, outside, pth.join(target, "link"), "junction");
            const zip = new Zip(archive({ "link/sub/": null }));
            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not write through a symlink nested below a real directory", function () {
            fs.mkdirSync(pth.join(target, "real"));
            makeLink(this, outside, pth.join(target, "real", "link"), "junction");
            const zip = new Zip(archive({ "real/link/victim.txt": "PWNED" }));
            expect(() => zip.extractAllTo(target, true)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });
    });

    describe("extractEntryTo", () => {
        it("does not overwrite a file outside the target through a file symlink", function () {
            makeLink(this, victim, pth.join(target, "victim.txt"), "file");
            const zip = new Zip(archive({ "victim.txt": "PWNED" }));
            expect(() => zip.extractEntryTo("victim.txt", target, true, true)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not write a file through a symlinked directory", function () {
            makeLink(this, outside, pth.join(target, "link"), "junction");
            const zip = new Zip(archive({ "link/payload.txt": "PWNED" }));
            expect(() => zip.extractEntryTo("link/payload.txt", target, true, false)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not write through a symlink named by outFileName", function () {
            makeLink(this, victim, pth.join(target, "renamed.txt"), "file");
            const zip = new Zip(archive({ "entry.txt": "PWNED" }));
            expect(() => zip.extractEntryTo("entry.txt", target, false, true, false, "renamed.txt")).to.throw(IN_THE_WAY);
            outsideUntouched();
        });

        it("does not write the children of a directory entry through a symlinked directory", function () {
            makeLink(this, outside, pth.join(target, "link"), "junction");
            const zip = new Zip(archive({ "link/": null, "link/payload.txt": "PWNED", "link/victim.txt": "PWNED" }));
            expect(() => zip.extractEntryTo("link/", target, true, true)).to.throw(IN_THE_WAY);
            outsideUntouched();
        });
    });

    describe("extractAllToAsync", () => {
        it("does not overwrite a file outside the target through a file symlink", function () {
            makeLink(this, victim, pth.join(target, "victim.txt"), "file");
            const zip = new Zip(archive({ "victim.txt": "PWNED" }));
            return expectRejected(zip.extractAllToAsync(target, true), IN_THE_WAY).then(outsideUntouched);
        });

        it("does not write a file through a symlinked directory", function () {
            makeLink(this, outside, pth.join(target, "link"), "junction");
            const zip = new Zip(archive({ "link/payload.txt": "PWNED", "link/victim.txt": "PWNED" }));
            return expectRejected(zip.extractAllToAsync(target, true), IN_THE_WAY).then(outsideUntouched);
        });

        it("does not create directories through a symlinked directory", function () {
            makeLink(this, outside, pth.join(target, "link"), "junction");
            const zip = new Zip(archive({ "link/sub/": null }));
            return expectRejected(zip.extractAllToAsync(target, true), /Unable to create folder/).then(outsideUntouched);
        });
    });

    describe("legitimate extraction keeps working", () => {
        const entries = { "dir/": null, "dir/a.txt": "A", "dir/sub/": null, "b.txt": "B" };
        const expectExtracted = (root) => {
            expect(fs.readFileSync(pth.join(root, "dir", "a.txt")).toString()).to.equal("A");
            expect(fs.readFileSync(pth.join(root, "b.txt")).toString()).to.equal("B");
            expect(fs.statSync(pth.join(root, "dir", "sub")).isDirectory()).to.equal(true);
        };

        it("extracts into a target without symlinks", () => {
            new Zip(archive(entries)).extractAllTo(target, true);
            expectExtracted(target);
            // overwriting regular files is still allowed
            new Zip(archive(entries)).extractAllTo(target, true);
            expectExtracted(target);
            new Zip(archive(entries)).extractEntryTo("dir/a.txt", target, true, true);
            expect(fs.readFileSync(pth.join(target, "dir", "a.txt")).toString()).to.equal("A");
        });

        it("extracts asynchronously into a target without symlinks", () => {
            return new Zip(archive(entries)).extractAllToAsync(target, true).then(() => expectExtracted(target));
        });

        it("extracts when the target directory itself is reached through a symlink", function () {
            const rootLink = pth.join(base, "root-link");
            makeLink(this, target, rootLink, "junction");
            new Zip(archive(entries)).extractAllTo(rootLink, true);
            expectExtracted(target);
            return new Zip(archive(entries)).extractAllToAsync(rootLink, true).then(() => expectExtracted(target));
        });
    });

    describe("Utils.assertPathSafe", () => {
        const utils = new Utils();

        it("accepts the root, missing paths and regular files below it", () => {
            fs.mkdirSync(pth.join(target, "dir"));
            fs.writeFileSync(pth.join(target, "dir", "file.txt"), "x");
            expect(() => utils.assertPathSafe(target, target)).to.not.throw();
            expect(() => utils.assertPathSafe(target, pth.join(target, "dir", "file.txt"))).to.not.throw();
            expect(() => utils.assertPathSafe(target, pth.join(target, "missing", "deeper", "file.txt"))).to.not.throw();
        });

        it("rejects a symlink at any depth below the root", function () {
            fs.mkdirSync(pth.join(target, "dir"));
            makeLink(this, outside, pth.join(target, "dir", "link"), "junction");
            expect(() => utils.assertPathSafe(target, pth.join(target, "dir", "link"))).to.throw(IN_THE_WAY);
            expect(() => utils.assertPathSafe(target, pth.join(target, "dir", "link", "victim.txt"))).to.throw(IN_THE_WAY);
        });

        it("is a no-op for a custom fs without lstatSync", () => {
            const custom = new Utils({ fs: { statSync: fs.statSync } });
            expect(() => custom.assertPathSafe(target, pth.join(target, "anything"))).to.not.throw();
        });
    });
});
