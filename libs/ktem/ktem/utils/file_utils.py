"""
Safe file handling utilities.

This module provides:
- Safe ZIP extraction (Zip Slip prevention)
- Temporary file management with cleanup
- File hashing and integrity checking
- Secure file operations
"""

import hashlib
import os
import shutil
import tempfile
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Generator, Iterator, Optional, Union
import tarfile
import gzip
import bz2


# =============================================================================
# Safe Archive Extraction
# =============================================================================

class ArchiveExtractionError(Exception):
    """Error during archive extraction."""
    pass


class PathTraversalError(ArchiveExtractionError):
    """Path traversal attack detected."""
    pass


@dataclass
class ExtractionResult:
    """Result of archive extraction."""
    success: bool
    extracted_path: Optional[Path] = None
    file_count: int = 0
    total_size: int = 0
    error_message: Optional[str] = None
    extracted_files: list[str] = None

    def __post_init__(self):
        if self.extracted_files is None:
            self.extracted_files = []


class SafeArchiveExtractor:
    """
    Safe archive extraction with path traversal prevention.

    Supports ZIP, TAR, GZIP, and BZIP2 archives.

    Usage:
        extractor = SafeArchiveExtractor(max_size_mb=100)
        result = extractor.extract_zip(archive_path, destination)

        if result.success:
            print(f"Extracted {result.file_count} files")
        else:
            print(f"Error: {result.error_message}")
    """

    # Default limits
    DEFAULT_MAX_SIZE_MB = 500
    DEFAULT_MAX_FILES = 10000
    DEFAULT_MAX_PATH_LENGTH = 255

    def __init__(
        self,
        max_size_mb: float = DEFAULT_MAX_SIZE_MB,
        max_files: int = DEFAULT_MAX_FILES,
        max_path_length: int = DEFAULT_MAX_PATH_LENGTH
    ):
        """
        Initialize safe archive extractor.

        Args:
            max_size_mb: Maximum total extracted size in MB
            max_files: Maximum number of files to extract
            max_path_length: Maximum path length for extracted files
        """
        self.max_size_bytes = int(max_size_mb * 1024 * 1024)
        self.max_files = max_files
        self.max_path_length = max_path_length

    def extract_zip(
        self,
        archive_path: Union[str, Path],
        destination: Union[str, Path],
        password: Optional[str] = None
    ) -> ExtractionResult:
        """
        Safely extract a ZIP archive.

        Args:
            archive_path: Path to ZIP file
            destination: Destination directory
            password: Optional archive password

        Returns:
            ExtractionResult with extraction details
        """
        archive_path = Path(archive_path)
        destination = Path(destination)

        if not archive_path.exists():
            return ExtractionResult(
                success=False,
                error_message=f"Archive not found: {archive_path}"
            )

        # Create destination directory
        destination.mkdir(parents=True, exist_ok=True)
        resolved_dest = destination.resolve()

        extracted_files = []
        total_size = 0

        try:
            with zipfile.ZipFile(archive_path, 'r') as zf:
                # Validate all members first
                members = zf.namelist()

                if len(members) > self.max_files:
                    return ExtractionResult(
                        success=False,
                        error_message=f"Too many files ({len(members)} > {self.max_files})"
                    )

                for member in members:
                    # Check path length
                    if len(member) > self.max_path_length:
                        return ExtractionResult(
                            success=False,
                            error_message=f"Path too long: {member[:50]}..."
                        )

                    # Validate path (prevent traversal)
                    member_path = (resolved_dest / member).resolve()
                    try:
                        member_path.relative_to(resolved_dest)
                    except ValueError:
                        raise PathTraversalError(f"Path traversal detected: {member}")

                    # Check total size
                    info = zf.getinfo(member)
                    if info.file_size > 0:
                        total_size += info.file_size
                        if total_size > self.max_size_bytes:
                            return ExtractionResult(
                                success=False,
                                error_message=f"Extracted size exceeds limit ({total_size} > {self.max_size_bytes})"
                            )

                # Extract files
                pwd = password.encode() if password else None
                for member in members:
                    member_path = (resolved_dest / member).resolve()

                    if member.endswith('/'):
                        # Directory
                        member_path.mkdir(parents=True, exist_ok=True)
                    else:
                        # File
                        member_path.parent.mkdir(parents=True, exist_ok=True)
                        with zf.open(member, pwd=pwd) as src:
                            with open(member_path, 'wb') as dst:
                                shutil.copyfileobj(src, dst)

                    extracted_files.append(str(member_path))

            return ExtractionResult(
                success=True,
                extracted_path=resolved_dest,
                file_count=len(extracted_files),
                total_size=total_size,
                extracted_files=extracted_files
            )

        except PathTraversalError as e:
            return ExtractionResult(
                success=False,
                error_message=str(e)
            )
        except zipfile.BadZipFile:
            return ExtractionResult(
                success=False,
                error_message="Invalid or corrupted ZIP file"
            )
        except Exception as e:
            return ExtractionResult(
                success=False,
                error_message=f"Extraction error: {str(e)}"
            )

    def extract_tar(
        self,
        archive_path: Union[str, Path],
        destination: Union[str, Path],
        compression: Optional[str] = None
    ) -> ExtractionResult:
        """
        Safely extract a TAR archive.

        Args:
            archive_path: Path to TAR file
            destination: Destination directory
            compression: Compression type ('gz', 'bz2', 'xz', or None)

        Returns:
            ExtractionResult with extraction details
        """
        archive_path = Path(archive_path)
        destination = Path(destination)

        if not archive_path.exists():
            return ExtractionResult(
                success=False,
                error_message=f"Archive not found: {archive_path}"
            )

        destination.mkdir(parents=True, exist_ok=True)
        resolved_dest = destination.resolve()

        # Determine open mode
        mode = 'r'
        if compression:
            mode = f'r:{compression}'
        elif archive_path.suffix == '.gz':
            mode = 'r:gz'
        elif archive_path.suffix == '.bz2':
            mode = 'r:bz2'
        elif archive_path.suffix == '.xz':
            mode = 'r:xz'

        extracted_files = []
        total_size = 0

        try:
            with tarfile.open(archive_path, mode) as tf:
                members = tf.getmembers()

                if len(members) > self.max_files:
                    return ExtractionResult(
                        success=False,
                        error_message=f"Too many files ({len(members)} > {self.max_files})"
                    )

                for member in members:
                    # Validate path
                    if len(member.name) > self.max_path_length:
                        return ExtractionResult(
                            success=False,
                            error_message=f"Path too long: {member.name[:50]}..."
                        )

                    member_path = (resolved_dest / member.name).resolve()
                    try:
                        member_path.relative_to(resolved_dest)
                    except ValueError:
                        raise PathTraversalError(f"Path traversal detected: {member.name}")

                    # Check size
                    if member.size > 0:
                        total_size += member.size
                        if total_size > self.max_size_bytes:
                            return ExtractionResult(
                                success=False,
                                error_message=f"Extracted size exceeds limit"
                            )

                    # Skip special file types (device nodes, symlinks to outside)
                    if member.issym() or member.islnk():
                        link_target = (resolved_dest / member.linkname).resolve()
                        try:
                            link_target.relative_to(resolved_dest)
                        except ValueError:
                            continue  # Skip symlinks pointing outside

                    if member.isdev() or member.isblk() or member.ischr():
                        continue  # Skip device nodes

                # Extract (using filter for safety on Python 3.12+)
                def safe_filter(tarinfo, path):
                    """Filter function for safe extraction."""
                    resolved = (Path(path) / tarinfo.name).resolve()
                    try:
                        resolved.relative_to(Path(path).resolve())
                        return tarinfo
                    except ValueError:
                        return None

                # Python 3.12+ has extraction_filter parameter
                try:
                    tf.extractall(resolved_dest, filter='data')
                except TypeError:
                    # Older Python - use manual extraction
                    for member in members:
                        member_path = (resolved_dest / member.name).resolve()
                        try:
                            member_path.relative_to(resolved_dest)
                        except ValueError:
                            continue
                        tf.extract(member, resolved_dest)

                    extracted_files = [str(resolved_dest / m.name) for m in members]

            return ExtractionResult(
                success=True,
                extracted_path=resolved_dest,
                file_count=len(members),
                total_size=total_size,
                extracted_files=extracted_files
            )

        except PathTraversalError as e:
            return ExtractionResult(success=False, error_message=str(e))
        except tarfile.TarError as e:
            return ExtractionResult(success=False, error_message=f"TAR error: {str(e)}")
        except Exception as e:
            return ExtractionResult(success=False, error_message=f"Extraction error: {str(e)}")

    def extract(
        self,
        archive_path: Union[str, Path],
        destination: Union[str, Path],
        **kwargs
    ) -> ExtractionResult:
        """
        Auto-detect archive type and extract.

        Args:
            archive_path: Path to archive
            destination: Destination directory
            **kwargs: Additional arguments for specific extractors

        Returns:
            ExtractionResult
        """
        archive_path = Path(archive_path)
        suffix = archive_path.suffix.lower()

        if suffix == '.zip':
            return self.extract_zip(archive_path, destination, **kwargs)
        elif suffix in ('.tar', '.tgz', '.tbz2', '.txz'):
            return self.extract_tar(archive_path, destination)
        elif suffix == '.gz' and archive_path.stem.endswith('.tar'):
            return self.extract_tar(archive_path, destination, compression='gz')
        elif suffix == '.bz2' and archive_path.stem.endswith('.tar'):
            return self.extract_tar(archive_path, destination, compression='bz2')
        else:
            return ExtractionResult(
                success=False,
                error_message=f"Unsupported archive format: {suffix}"
            )


# Global extractor instance
safe_extractor = SafeArchiveExtractor()


def safe_extract_zip(
    archive_path: Union[str, Path],
    destination: Union[str, Path],
    **kwargs
) -> ExtractionResult:
    """Convenience function for safe ZIP extraction."""
    return safe_extractor.extract_zip(archive_path, destination, **kwargs)


def safe_extract_archive(
    archive_path: Union[str, Path],
    destination: Union[str, Path],
    **kwargs
) -> ExtractionResult:
    """Convenience function for safe archive extraction (auto-detect type)."""
    return safe_extractor.extract(archive_path, destination, **kwargs)


# =============================================================================
# Temporary File Management
# =============================================================================

class TempFileManager:
    """
    Managed temporary files with automatic cleanup.

    Ensures temporary files are always cleaned up, even on errors.

    Usage:
        with TempFileManager() as tmp:
            temp_file = tmp.create_file(suffix=".txt")
            temp_dir = tmp.create_directory()
            # Use files...
        # Files automatically cleaned up

        # Or track globally:
        manager = TempFileManager()
        path = manager.create_file()
        # ...
        manager.cleanup()  # Manual cleanup
    """

    def __init__(self, base_dir: Optional[Union[str, Path]] = None):
        """
        Initialize temp file manager.

        Args:
            base_dir: Base directory for temp files (default: system temp)
        """
        self.base_dir = Path(base_dir) if base_dir else None
        self._files: list[Path] = []
        self._dirs: list[Path] = []

    def create_file(
        self,
        suffix: str = "",
        prefix: str = "tmp_",
        content: Optional[bytes] = None
    ) -> Path:
        """
        Create a managed temporary file.

        Args:
            suffix: File suffix (e.g., ".txt")
            prefix: File prefix
            content: Optional initial content

        Returns:
            Path to temporary file
        """
        fd, path = tempfile.mkstemp(
            suffix=suffix,
            prefix=prefix,
            dir=self.base_dir
        )
        path = Path(path)
        self._files.append(path)

        if content:
            with os.fdopen(fd, 'wb') as f:
                f.write(content)
        else:
            os.close(fd)

        return path

    def create_directory(self, prefix: str = "tmp_") -> Path:
        """
        Create a managed temporary directory.

        Args:
            prefix: Directory prefix

        Returns:
            Path to temporary directory
        """
        path = Path(tempfile.mkdtemp(prefix=prefix, dir=self.base_dir))
        self._dirs.append(path)
        return path

    def cleanup(self) -> None:
        """Remove all managed temporary files and directories."""
        for file_path in self._files:
            try:
                if file_path.exists():
                    file_path.unlink()
            except Exception:
                pass

        for dir_path in self._dirs:
            try:
                if dir_path.exists():
                    shutil.rmtree(dir_path, ignore_errors=True)
            except Exception:
                pass

        self._files.clear()
        self._dirs.clear()

    def __enter__(self) -> 'TempFileManager':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def __del__(self) -> None:
        self.cleanup()


@contextmanager
def temp_file(
    suffix: str = "",
    prefix: str = "tmp_",
    content: Optional[bytes] = None
) -> Generator[Path, None, None]:
    """
    Context manager for a single temporary file.

    Usage:
        with temp_file(suffix=".json") as path:
            path.write_text('{"key": "value"}')
            # Use the file...
        # File automatically deleted
    """
    manager = TempFileManager()
    try:
        yield manager.create_file(suffix=suffix, prefix=prefix, content=content)
    finally:
        manager.cleanup()


@contextmanager
def temp_directory(prefix: str = "tmp_") -> Generator[Path, None, None]:
    """
    Context manager for a temporary directory.

    Usage:
        with temp_directory() as tmpdir:
            (tmpdir / "file.txt").write_text("content")
            # Use the directory...
        # Directory automatically deleted
    """
    manager = TempFileManager()
    try:
        yield manager.create_directory(prefix=prefix)
    finally:
        manager.cleanup()


# =============================================================================
# File Hashing
# =============================================================================

def compute_file_hash(
    file_path: Union[str, Path, BinaryIO],
    algorithm: str = "sha256",
    chunk_size: int = 65536
) -> str:
    """
    Compute hash of a file.

    Args:
        file_path: Path to file or file-like object
        algorithm: Hash algorithm (sha256, sha1, md5)
        chunk_size: Chunk size for reading

    Returns:
        Hexadecimal hash string
    """
    hasher = hashlib.new(algorithm)

    if isinstance(file_path, (str, Path)):
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(chunk_size), b''):
                hasher.update(chunk)
    else:
        # File-like object
        pos = file_path.tell() if hasattr(file_path, 'tell') else 0
        for chunk in iter(lambda: file_path.read(chunk_size), b''):
            hasher.update(chunk)
        if hasattr(file_path, 'seek'):
            file_path.seek(pos)

    return hasher.hexdigest()


def verify_file_hash(
    file_path: Union[str, Path],
    expected_hash: str,
    algorithm: str = "sha256"
) -> bool:
    """
    Verify file integrity using hash.

    Args:
        file_path: Path to file
        expected_hash: Expected hash value
        algorithm: Hash algorithm used

    Returns:
        True if hash matches
    """
    import hmac
    actual_hash = compute_file_hash(file_path, algorithm)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.lower())


# =============================================================================
# Secure File Operations
# =============================================================================

def secure_delete(file_path: Union[str, Path], passes: int = 3) -> bool:
    """
    Securely delete a file by overwriting with random data.

    Note: May not work on SSDs due to wear leveling.

    Args:
        file_path: Path to file
        passes: Number of overwrite passes

    Returns:
        True if successful
    """
    file_path = Path(file_path)

    if not file_path.exists():
        return False

    try:
        file_size = file_path.stat().st_size

        with open(file_path, 'r+b') as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())

        file_path.unlink()
        return True
    except Exception:
        # Fall back to regular delete
        try:
            file_path.unlink()
            return True
        except Exception:
            return False


def safe_write_file(
    file_path: Union[str, Path],
    content: Union[str, bytes],
    encoding: str = 'utf-8',
    atomic: bool = True
) -> bool:
    """
    Safely write content to a file.

    Uses atomic write (write to temp, then rename) to prevent corruption.

    Args:
        file_path: Destination path
        content: Content to write
        encoding: Text encoding (for str content)
        atomic: Use atomic write

    Returns:
        True if successful
    """
    file_path = Path(file_path)

    try:
        if atomic:
            # Write to temp file first
            fd, temp_path = tempfile.mkstemp(
                dir=file_path.parent,
                prefix=f".{file_path.name}."
            )

            try:
                mode = 'wb' if isinstance(content, bytes) else 'w'
                with os.fdopen(fd, mode, encoding=None if isinstance(content, bytes) else encoding) as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())

                # Atomic rename
                os.replace(temp_path, file_path)
                return True

            except Exception:
                # Clean up temp file on error
                try:
                    os.unlink(temp_path)
                except Exception:
                    pass
                raise

        else:
            # Direct write
            mode = 'wb' if isinstance(content, bytes) else 'w'
            with open(file_path, mode, encoding=None if isinstance(content, bytes) else encoding) as f:
                f.write(content)
            return True

    except Exception:
        return False


def copy_file_safe(
    src: Union[str, Path],
    dst: Union[str, Path],
    verify_hash: bool = True
) -> bool:
    """
    Safely copy a file with optional integrity verification.

    Args:
        src: Source file path
        dst: Destination path
        verify_hash: Verify integrity after copy

    Returns:
        True if successful (and verified if requested)
    """
    src = Path(src)
    dst = Path(dst)

    try:
        # Get source hash before copy
        src_hash = compute_file_hash(src) if verify_hash else None

        # Create destination directory
        dst.parent.mkdir(parents=True, exist_ok=True)

        # Copy to temp file first
        with TempFileManager() as tmp:
            temp_dst = tmp.create_file(suffix=dst.suffix)

            with open(src, 'rb') as fsrc:
                with open(temp_dst, 'wb') as fdst:
                    shutil.copyfileobj(fsrc, fdst)

            # Verify if requested
            if verify_hash:
                dst_hash = compute_file_hash(temp_dst)
                if src_hash != dst_hash:
                    return False

            # Move to final destination
            shutil.move(str(temp_dst), str(dst))
            tmp._files.remove(temp_dst)  # Don't clean up - it was moved

        return True

    except Exception:
        return False
