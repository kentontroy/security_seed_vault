// Package vault: archive.go adds the tar+gzip layer on top of the streaming
// AEAD, so you can encrypt a whole folder to a single file and restore it.
//
// Pipeline (encrypt):  folder -> tar -> gzip -> AES-256-GCM stream -> .tar.gz.enc
// Pipeline (decrypt):  .tar.gz.enc -> AES-256-GCM stream -> gunzip -> untar -> folder
//
// Compression happens BEFORE encryption (encrypted data is incompressible).
// Everything is streamed: memory use stays flat regardless of archive size.
package vault

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// EncryptFolder tars+gzips srcDir and writes the encrypted archive to outPath.
func EncryptFolder(srcDir, outPath string, key []byte) error {
	info, err := os.Stat(srcDir)
	if err != nil {
		return fmt.Errorf("source: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", srcDir)
	}

	out, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("creating output: %w", err)
	}
	defer out.Close()

	// Build the pipe chain: tar+gzip write into pw; Encrypt reads from pr.
	pr, pw := io.Pipe()

	go func() {
		gz := gzip.NewWriter(pw)
		tw := tar.NewWriter(gz)
		werr := filepath.Walk(srcDir, func(path string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			// Store paths relative to srcDir's parent so the top folder name is kept.
			rel, err := filepath.Rel(filepath.Dir(srcDir), path)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)

			// Resolve symlink target (stored as a link entry; not followed).
			link := ""
			if fi.Mode()&os.ModeSymlink != 0 {
				link, _ = os.Readlink(path)
			}
			hdr, err := tar.FileInfoHeader(fi, link)
			if err != nil {
				return err
			}
			hdr.Name = rel
			if fi.IsDir() && !strings.HasSuffix(hdr.Name, "/") {
				hdr.Name += "/"
			}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if fi.Mode().IsRegular() {
				f, err := os.Open(path)
				if err != nil {
					return err
				}
				defer f.Close()
				if _, err := io.Copy(tw, f); err != nil {
					return err
				}
			}
			return nil
		})
		// Close in order; propagate the first error to the reader side.
		if werr == nil {
			werr = tw.Close()
		} else {
			_ = tw.Close()
		}
		if werr == nil {
			werr = gz.Close()
		} else {
			_ = gz.Close()
		}
		pw.CloseWithError(werr)
	}()

	if err := Encrypt(out, pr, key, DefaultSegmentSize); err != nil {
		return fmt.Errorf("encrypting: %w", err)
	}
	return nil
}

// DecryptFolder decrypts inPath and extracts the archive into destDir.
// Extraction is guarded against path-traversal ("zip slip").
func DecryptFolder(inPath, destDir string, key []byte) error {
	in, err := os.Open(inPath)
	if err != nil {
		return fmt.Errorf("opening input: %w", err)
	}
	defer in.Close()

	if err := os.MkdirAll(destDir, 0o700); err != nil {
		return fmt.Errorf("creating dest: %w", err)
	}

	pr, pw := io.Pipe()

	// Decrypt writes plaintext (the gzip stream) into pw; the extractor reads pr.
	go func() {
		err := Decrypt(pw, in, key)
		pw.CloseWithError(err)
	}()

	gz, err := gzip.NewReader(pr)
	if err != nil {
		return fmt.Errorf("gzip: %w (wrong key, or corrupted/tampered archive)", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	cleanDest, err := filepath.Abs(destDir)
	if err != nil {
		return err
	}
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading archive: %w (wrong key or tampering)", err)
		}

		target := filepath.Join(cleanDest, filepath.FromSlash(hdr.Name))
		// zip-slip guard: ensure target stays within destDir.
		if !strings.HasPrefix(target, cleanDest+string(os.PathSeparator)) && target != cleanDest {
			return fmt.Errorf("unsafe path in archive: %q", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, fs(hdr.Mode)); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, fs(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			_ = os.Remove(target)
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return err
			}
		default:
			// Skip devices/fifos etc.; not expected for personal document vaults.
		}
	}
	return nil
}

func fs(mode int64) os.FileMode { return os.FileMode(mode) & os.ModePerm }
