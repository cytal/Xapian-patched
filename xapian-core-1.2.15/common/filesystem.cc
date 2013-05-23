/** @file filesystem.cc
 *  @brief File and path manipulation routines.
 */
/* Copyright (C) 2008 Lemur Consulting Ltd
 * Copyright (C) 2008,2009,2010 Olly Betts
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
 */

#include <config.h>

#include "fileutils.h"
#include "io_utils.h"
#include "utils.h"
#include <xapian/filesystem.h>
#include <xapian/error.h>

#include <cstring>
#include <string>
#include <sstream>

#ifdef __WIN32__
	# include "msvc_posix_wrapper.h"
#else
	#include "safefcntl.h"
	#include <unistd.h>
	#include <cstdlib>
	#include <sys/socket.h>
	#include <sys/wait.h>
	#include <signal.h>
	#include <cstring>
#endif

#include "closefrom.h"
#include "omassert.h"

#ifdef __CYGWIN__
	#include <sys/cygwin.h>
#endif

#if defined __CYGWIN__ || defined __WIN32__
	# include "safewindows.h"
#elif defined __EMX__
	# define INCL_DOS
	# define INCL_DOSERRORS
	# include <os2.h>
#endif

#include "safeerrno.h"
#include "safesysstat.h"

#include <sys/types.h>
#include <memory>

namespace Xapian {

File::Internal::~Internal() {}

//////////////////////////////////////////////////////////////////////////

FileSystem::Internal::~Internal() {}

bool FileSystem::load_file_to_string( const std::string & file, std::string & content)
{
	File f = open( file, O_RDONLY | O_BINARY, 0666 );
	if ( !f.is_opened() )
		return false;
	f.load_to_string( content );
	return true;
}

bool FileSystem::io_unlink( const std::string & file ) 
{
	if ( get_internal().unlink( file ) )
		return true;
	else if ( errno != ENOENT)
		throw Xapian::DatabaseError(file + ": delete failed", errno);
	return false;
}

//////////////////////////////////////////////////////////////////////////

void File::load_to_string( std::string & s )
{
	if ( !is_opened() )
		return;
	const size_t cache_size = 1024 * 64;
	char * buf = new char[ cache_size ];

	int r = 0;
	while ( (r = internal->read_data( buf, cache_size)) > 0 )
		s.append( buf, r );
	delete []buf;
}

void File::io_write(const char * p, size_t n )
{
	if ( !is_opened() )
		throw Xapian::DatabaseError("File not opened to write", errno);

	while (n) {
		ssize_t c = internal->write_data( p, n);
		if (c < 0) {
			if (errno == EINTR) continue;
			throw Xapian::DatabaseError("Error writing to file", errno);
		}
		p += c;
		n -= c;
	}
}

size_t File::io_read(char * p, size_t n, size_t min)
{
	if ( !is_opened() )
		throw Xapian::DatabaseError("File not opened to read", errno);

	size_t total = 0;
	while (n) {
		ssize_t c = read_data( p, n);
		if (c <= 0) {
			if (c == 0) {
				if (total >= min) break;
				throw Xapian::DatabaseError("Couldn't read enough (EOF)");
			}
			if (errno == EINTR) continue;
			throw Xapian::DatabaseError("Error reading from file", errno);
		}
		p += c;
		total += c;
		n -= c;
	}
	return total;
}

//////////////////////////////////////////////////////////////////////////

class StandardFileInternal : public File::Internal
{
public:
	StandardFileInternal(int h) : handle(h) {}
	~StandardFileInternal() { close(); }

	virtual int		read_data( void * data, size_t size );
	virtual int		write_data( const void * data, size_t size);
	virtual off_t	seek( off_t off , int mod = SEEK_SET );
	virtual off_t	tell();
	virtual void	close();
	virtual bool	sync();
	virtual off_t	get_size();
	virtual bool	is_opened();
	virtual std::string	debug();
protected:
	int				handle;
};

//////////////////////////////////////////////////////////////////////////

std::string	StandardFileInternal::debug()
{
	std::stringstream	o;
	o << handle;
	return o.str();
}

int StandardFileInternal::read_data(void * data, size_t size)
{
	if ( handle == -1 )
		return -1;
	char * p = reinterpret_cast<char *>( data );
	while (size) {
		ssize_t c = static_cast<ssize_t>( read( handle, p, static_cast<int>(size) ) );
		if (c < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		} else if ( c == 0 )
			break;
		p += c;
		size -= c;
	}
	return static_cast<int>( p - reinterpret_cast<char *>( data ) );
}

int StandardFileInternal::write_data(const void * data, size_t size)
{
	if ( handle == -1 )
		return -1;
	const char * p = reinterpret_cast<const char *>( data );
	while (size) {
		ssize_t c = static_cast<ssize_t>( write( handle, p, static_cast<int>(size) ) );
		if (c <= 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		p += c;
		size -= c;
	}
	return static_cast<int>( p - reinterpret_cast<const char *>( data ) );
}

bool StandardFileInternal::sync()
{
	if ( handle == -1 )
		return false;
	return io_sync( handle );
}

void StandardFileInternal::close()
{
	if ( handle >= 0 ) {
		::close( handle ); 
		handle = -1;
	}
}

bool StandardFileInternal::is_opened() 
{
	return handle >= 0; 
}

off_t StandardFileInternal::seek( off_t off , int mod )
{
	if ( handle == -1 )
		return -1;
	return static_cast<off_t>( lseek( handle, off, mod ) );
}

off_t StandardFileInternal::tell()
{
	return seek( 0, SEEK_CUR );
}

off_t	StandardFileInternal::get_size()
{
	struct stat sb;
	if (fstat(handle, &sb) == -1)
		throw Xapian::NetworkError("Couldn't stat file to send", errno);
	return static_cast<off_t>( sb.st_size );
}

//////////////////////////////////////////////////////////////////////////

class StandardFileSystemInternal : public FileSystem::Internal
{
public:
	StandardFileSystemInternal() {}

	virtual File	open(const std::string & path, int flags, int mod);
	virtual bool	make_dir( const std::string & path, int mod );
	virtual bool	remove_dir(const std::string & path );
	virtual bool	unlink( const std::string & file );
	virtual void *	lock_file( const std::string & filename, bool exclusive, FileSystem::reason & r, std::string & explanation );
	virtual void	unlock_file( const std::string & filename, void * pContext );
	virtual bool	rename(const std::string & oldname, const std::string & newname);
	virtual bool	path_exist(const std::string & file, FileState * pState);

	virtual std::string get_description() const;
};

//////////////////////////////////////////////////////////////////////////

File StandardFileSystemInternal::open(const std::string & full, int flags, int mod)
{
#ifdef __WIN32__
	int fd = msvc_posix_open( full.c_str(), flags );
#else
	int fd = ::open( full.c_str(), flags, mod );
#endif
	return File( new StandardFileInternal(fd) );
}

bool StandardFileSystemInternal::make_dir( const std::string & path, int mod )
{
	struct stat statbuf;
	if (stat(path.c_str(), &statbuf) == 0) {
		if (!S_ISDIR(statbuf.st_mode)) 
			return false;
	} else if (errno != ENOENT || mkdir(path.c_str(), mod) == -1) {
		return false;
	}
	return true;
}

bool StandardFileSystemInternal::remove_dir(const std::string & path )
{
	removedir( path );
	return true;
}

bool StandardFileSystemInternal::rename(const std::string & oldname, const std::string & newname)
{
#if defined __WIN32__
	return msvc_posix_rename( oldname.c_str(), newname.c_str() ) >= 0;
#else
	return ::rename(oldname.c_str(), newname.c_str() ) >= 0;
#endif
}

bool StandardFileSystemInternal::unlink( const std::string & file )
{
	return ::unlink(file.c_str()) == 0 || errno == ENOENT;
}

bool StandardFileSystemInternal::path_exist(const std::string & file, FileState * pState )
{
	struct stat sb;
	if ( stat(file.c_str(), &sb) == 0) {
		if ( pState != NULL )
			pState->set( S_ISREG(sb.st_mode), S_ISDIR(sb.st_mode), sb.st_ctime, sb.st_mtime, sb.st_atime, static_cast<off_t>(sb.st_size) );
		return true;
	}
	return false;
}

struct StandardLockContext
{
#if defined __CYGWIN__ || defined __WIN32__
	HANDLE hFile;
	StandardLockContext() : hFile(INVALID_HANDLE_VALUE) {}
#elif defined __EMX__
	HFILE hFile;
	StandardLockContext() : hFile(NULLHANDLE) {}
#else
	int fd;
	pid_t pid;
	StandardLockContext() : fd(-1) {}
#endif
};

void * StandardFileSystemInternal::lock_file( const std::string & filename, bool, FileSystem::reason & r, std::string & explanation )
{
	std::auto_ptr<StandardLockContext>	pContext( new StandardLockContext );

#if defined __CYGWIN__ || defined __WIN32__

#ifdef __CYGWIN__
	char fnm[MAX_PATH];
	cygwin_conv_to_win32_path(filename.c_str(), fnm);
#else
	const char *fnm = filename.c_str();
#endif

	pContext->hFile = CreateFile(fnm, GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if ( pContext->hFile != INVALID_HANDLE_VALUE)  {
		r = FileSystem::SUCCESS;
		return pContext.release();
	}
	if (GetLastError() == ERROR_ALREADY_EXISTS) {
		r = FileSystem::INUSE;
		return NULL;
	}
	r = FileSystem::UNKNOWN;
	return NULL;

#elif defined __EMX__

	APIRET rc;
	ULONG ulAction;
	rc = DosOpen((PCSZ)filename.c_str(), &pContext->hFile, &ulAction, 0, FILE_NORMAL,
		OPEN_ACTION_OPEN_IF_EXISTS | OPEN_ACTION_CREATE_IF_NEW, OPEN_SHARE_DENYWRITE | OPEN_ACCESS_WRITEONLY, NULL);
	if (rc == NO_ERROR) {
		r = FileSystem::SUCCESS;
		return pContext.release();
	}
	if (rc == ERROR_ACCESS_DENIED) {
		r = FileSystem::INUSE;
		return NULL;
	}
	r = FileSystem::UNKNOWN;
	return NULL;

#else

	int lockfd = ::open( filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (lockfd < 0) {
		// Couldn't open lockfile.
		explanation = string("Couldn't open lockfile: ") + strerror(errno);
		r = ((errno == EMFILE || errno == ENFILE) ? FileSystem::FDLIMIT : FileSystem::UNKNOWN);
		return NULL;
	}

	// If stdin and/or stdout have been closed, it is possible that lockfd could
	// be 0 or 1.  We need fds 0 and 1 to be available in the child process to
	// be stdin and stdout, and we can't use dup() on lockfd after locking it,
	// as the lock won't be transferred, so we handle this corner case here by
	// using dup() once or twice to get lockfd to be >= 2.
	if (rare(lockfd < 2)) {
		// Note this temporarily requires one or two spare fds to work, but
		// then we need two spare for socketpair() to succeed below anyway.
		int lockfd_dup = dup(lockfd);
		if (rare(lockfd_dup < 2)) {
			int eno = 0;
			if (lockfd_dup < 0) {
				eno = errno;
				close(lockfd);
			} else {
				int lockfd_dup2 = dup(lockfd);
				if (lockfd_dup2 < 0) {
					eno = errno;
				}
				close(lockfd);
				close(lockfd_dup);
				lockfd = lockfd_dup2;
			}
			if (eno) {
				r = ((errno == EMFILE || errno == ENFILE) ? FileSystem::FDLIMIT : FileSystem::UNKNOWN);
				return NULL;
			}
		} else {
			close(lockfd);
			lockfd = lockfd_dup;
		}
	}

	int fds[2];
	if (socketpair(AF_UNIX, SOCK_STREAM, PF_UNSPEC, fds) < 0) {
		// Couldn't create socketpair.
		explanation = string("Couldn't create socketpair: ") + strerror(errno);
		r = ((errno == EMFILE || errno == ENFILE) ? FileSystem::FDLIMIT : FileSystem::UNKNOWN);
		(void)close(lockfd);
		return NULL;
	}

	pid_t child = fork();

	if (child == 0) {
		// Child process.
		close(fds[0]);

		// Connect pipe to stdin and stdout.
		dup2(fds[1], 0);
		dup2(fds[1], 1);

		// Make sure we don't hang on to open files which may get deleted but
		// not have their disk space released until we exit.  Close these
		// before we try to get the lock because if one of them is open on
		// the lock file then closing it after obtaining the lock would release
		// the lock, which would be really bad.
		for (int i = 2; i < lockfd; ++i) {
			// Retry on EINTR; just ignore other errors (we'll get
			// EBADF if the fd isn't open so that's OK).
			while (close(i) < 0 && errno == EINTR) { }
		}
		closefrom(lockfd + 1);

		r = FileSystem::SUCCESS;
		{
			struct flock fl;
			fl.l_type = F_WRLCK;
			fl.l_whence = SEEK_SET;
			fl.l_start = 0;
			fl.l_len = 1;
			while (fcntl(lockfd, F_SETLK, &fl) == -1) {
				if (errno != EINTR) {
					// Lock failed - translate known errno values into a reason
					// code.
					if (errno == EACCES || errno == EAGAIN) {
						r = FileSystem::INUSE;
					} else if (errno == ENOLCK) {
						r = FileSystem::UNSUPPORTED;
					} else {
						_exit(0);
					}
					break;
				}
			}
		}

		{
			// Tell the parent if we got the lock, and if not, why not.
			char ch = static_cast<char>(r);
			while (write(1, &ch, 1) < 0) {
				// EINTR means a signal interrupted us, so retry.
				// Otherwise we're DOOMED!  The best we can do is just exit
				// and the parent process should get EOF and know the lock
				// failed.
				if (errno != EINTR) _exit(1);
			}
			if (r != FileSystem::SUCCESS) _exit(0);
		}

		// Make sure we don't block unmount() of partition holding the current
		// directory.
		if (chdir("/") < 0) {
			// We can't usefully do anything in response to an error, so just
			// ignore it - the worst harm it can do is make it impossible to
			// unmount a partition.
			//
			// We need the if statement because glibc's _FORTIFY_SOURCE mode
			// gives a warning even if we cast the result to void.
		}

		// FIXME: use special statically linked helper instead of cat.
		execl("/bin/cat", "/bin/cat", static_cast<void*>(NULL));
		// Emulate cat ourselves (we try to avoid this to reduce VM overhead).
		char ch;
		while (read(0, &ch, 1) != 0) { /* Do nothing */ }
		_exit(0);
	}

	close(lockfd);
	close(fds[1]);

	if (child == -1) {
		// Couldn't fork.
		explanation = string("Couldn't fork: ") + strerror(errno);
		close(fds[0]);
		r = FileSystem::UNKNOWN;
		return NULL;
	}

	r = FileSystem::UNKNOWN;

	// Parent process.
	while (true) {
		char ch;
		ssize_t n = read(fds[0], &ch, 1);
		if (n == 1) {
			r = static_cast<FileSystem::reason>(ch);
			if (r != FileSystem::SUCCESS) break;
			// Got the lock.
			pContext->fd = fds[0];
			pContext->pid = child;
			r = FileSystem::SUCCESS;
			return pContext.release();
		}
		if (n == 0) {
			// EOF means the lock failed.
			explanation.assign("Got EOF reading from child process");
			break;
		}
		if (errno != EINTR) {
			// Treat unexpected errors from read() as failure to get the lock.
			explanation = string("Error reading from child process: ") + strerror(errno);
			break;
		}
	}

	close(fds[0]);

	int status;
	while (waitpid(child, &status, 0) < 0) {
		if (errno != EINTR) break;
	}

	return NULL;
#endif
}

void StandardFileSystemInternal::unlock_file( const std::string &, void * pContext_ )
{
	std::auto_ptr<StandardLockContext>	pContext( reinterpret_cast<StandardLockContext *>(pContext_) );

#if defined __CYGWIN__ || defined __WIN32__
	if ( pContext_ == NULL || pContext->hFile == INVALID_HANDLE_VALUE) 
		return;
	CloseHandle( pContext->hFile );
#elif defined __EMX__
	if ( pContext_ == NULL || pContext->hFile == NULLHANDLE) 
		return;
	DosClose( pContext->hFile );
#else
	if (pContext_ == NULL || pContext->fd < 0) return;
	close( pContext->fd );

	// Kill the child process which is holding the lock.  Use SIGKILL since
	// that can't be caught or ignored (we used to use SIGHUP, but if the
	// application has set that to SIG_IGN, the child process inherits that
	// setting, which sometimes results in the child process not exiting -
	// noted on Linux).
	//
	// The only likely error from kill is ESRCH (pid doesn't exist).  The other
	// possibilities (according to the Linux man page) are EINVAL (invalid
	// signal) and EPERM (don't have permission to SIGKILL the process) but in
	// none of the cases does calling waitpid do us any good!
	if (kill(pContext->pid, SIGKILL) == 0) {
		int status;
		while (waitpid(pContext->pid, &status, 0) < 0) {
			if (errno != EINTR) break;
		}
	}
#endif
	
}

std::string StandardFileSystemInternal::get_description() const
{
	return "Standard File System";
}

//////////////////////////////////////////////////////////////////////////

FileSystem::Internal	&	FileSystem::get_internal()
{
	if ( internal.get() == NULL )
		internal = new StandardFileSystemInternal;
	return *internal;
}

File FileSystem::create_changeset_file( const std::string & path, const std::string & name, std::string & changes_name )
{
	changes_name = path + "/" + name;
	File res = open( changes_name, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0666 );
	if ( !res.is_opened() ) {
		std::string message("Couldn't open changeset to write: ");
		message += changes_name;
		throw Xapian::DatabaseError(message, errno);
	}
	return res;
}

//////////////////////////////////////////////////////////////////////////

FileSystem::reason FileLock::lock(bool exclusive, std::string & explanation)
{
	release();
	FileSystem::reason r;
	context = file_system.lock_file( filename, exclusive, r, explanation );
	return r;
}

void FileLock::release()
{
	if ( context != NULL ) {
		file_system.unlock_file( filename, context );
		context = NULL;
	}

}

void FileLock::throw_databaselockerror( FileSystem::reason why, const std::string & db_dir, const std::string & explanation)
{
	std::string msg("Unable to get write lock on ");
	msg += db_dir;
	if (why == FileSystem::INUSE) {
		msg += ": already locked";
	} else if (why == FileSystem::UNSUPPORTED) {
		msg += ": locking probably not supported by this FS";
	} else if (why == FileSystem::FDLIMIT) {
		msg += ": too many open files";
	} else if (why == FileSystem::UNKNOWN) {
		if (!explanation.empty())
			msg += ": " + explanation;
	}
	throw Xapian::DatabaseLockError(msg);
}

}
