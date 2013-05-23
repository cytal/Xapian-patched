/** \file  filesystem.h
 *  \brief filesystem define
 */
/* Copyright (C) 2005,2007,2010 Olly Betts
 * Copyright (C) 2010 Evgeny Sizikov
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#ifndef XAPIAN_INCLUDED_FILESYSTEM_H
#define XAPIAN_INCLUDED_FILESYSTEM_H

#include <xapian/base.h>
#include <xapian/visibility.h>

#include <fcntl.h>
#include <sys/types.h>

#include <string>

namespace Xapian {

class XAPIAN_VISIBILITY_DEFAULT FileState
{
public:
	FileState() : is_file(false),is_dir(false), time_create(0), time_mod(0), time_access(0), size(0) {}

	void	set( bool boIsFile, bool boIsDir, time_t tCreate, time_t tMod, time_t tAccess, off_t nSize)
	{
		is_file = boIsFile;
		is_dir = boIsDir;
		time_create = tCreate;
		time_mod = tMod;
		time_access = tAccess;
		size = nSize;
	}

	bool	isFile() const { return is_file; }
	bool	isDir() const { return is_dir; }
	time_t	create_time() const { return time_create; }
	time_t	modify_time() const { return time_mod; }
	time_t	access_time() const { return time_access; }
	off_t	file_size() const { return size; }
protected:
	bool	is_file;
	bool	is_dir;
	time_t	time_create, time_mod, time_access;
	off_t	size;
};

class XAPIAN_VISIBILITY_DEFAULT File
{
public:
	class Internal;

	File() {}
	File(const File & f) : internal( f.internal ) {}
	explicit File( File::Internal * internal_ ) : internal( internal_ ) {}

	~File() {}

	bool	is_opened() const { return internal.get() != NULL && internal->is_opened(); }
	int		pread(void * data, size_t size, off_t off) 	{
		return ( is_opened() && internal->seek( off ) == off ) ? internal->read_data( data, size ) : -1;
	}
	int		pwrite(const void * data, size_t size, off_t off) {
		return ( is_opened() && internal->seek( off ) == off ) ? internal->write_data( data, size ) : -1;
	}
	int		read_data(void * data, size_t size) 	{
		return is_opened() ? internal->read_data( data, size ) : -1;
	}
	int		write_data(const void * data, size_t size) {
		return is_opened() ? internal->write_data( data, size ) : -1;
	}
	off_t	seek( off_t off , int mod = SEEK_SET ) {
		return is_opened() ? internal->seek( off, mod ) : -1;
	}
	void	close() {
		if ( is_opened() ) {
			internal->close();
			internal = NULL;
		}
	}
	File & operator=(const File & f) {
		if ( &f != this ) {
			internal = f.internal;
		}
		return *this;
	}

	void	io_write(const char * p, size_t n);
	size_t	io_read(char * p, size_t n, size_t min);
	bool	io_sync() { return is_opened() ? internal->sync() : false; }
	off_t	get_size() { return is_opened() ? internal->get_size() : 0; }
	void	load_to_string( std::string & s );

	void	write_and_clear_changes(std::string & buf, size_t bytes)
	{
		if ( is_opened() )
			io_write( buf.data(), bytes );
		buf.erase(0, bytes);
	}

	class Internal : public Xapian::Internal::RefCntBase
	{
	public:
		Internal() {};
		virtual ~Internal();
		virtual int		read_data( void * data, size_t size ) = 0;
		virtual int		write_data( const void * data, size_t size) = 0;
		virtual off_t	seek( off_t off , int mod = SEEK_SET ) = 0;
		virtual off_t	tell() = 0;
		virtual void	close() = 0;
		virtual bool	sync() = 0;
		virtual off_t	get_size() = 0;
		virtual bool	is_opened() = 0;
		virtual std::string	debug() = 0;
	private:
		/// Copies are not allowed.
		Internal(const Internal &);
		/// Assignment is not allowed.
		void operator=(const Internal &);
	};

	std::string		debug() { return is_opened() ? internal->debug() : std::string("nullfile"); }
protected:
	Xapian::Internal::RefCntPtr<Internal>	internal;
};

class XAPIAN_VISIBILITY_DEFAULT FileSystem
{
public:
	class Internal;

	FileSystem() {}
	FileSystem(const FileSystem & f) : internal( f.internal ) {}
	explicit FileSystem( FileSystem::Internal * internal_ ) : internal( internal_ ) {}

	File	open(const std::string & path, int flags, int mod) {
		return get_internal().open( path, flags, mod );
	}

	bool	load_file_to_string( const std::string & file, std::string & content);

	bool	make_dir( const std::string & path, int mod ) {
		return get_internal().make_dir( path, mod );
	}
	bool	remove_dir(const std::string & path ) {
		return get_internal().remove_dir( path );
	}
	bool	unlink( const std::string & file ) {
		return get_internal().unlink( file );
	}
	bool	io_unlink( const std::string & file  );
	
	bool	path_exist(const std::string & file, FileState * pState = NULL ) {
		return get_internal().path_exist( file, pState );
	}

	bool	file_exist(const std::string & file ) {
		FileState State;
		return get_internal().path_exist( file, &State ) && State.isFile();
	}
	bool	dir_exist(const std::string & file ) {
		FileState State;
		return get_internal().path_exist( file, &State ) && State.isDir();
	}

	typedef enum {
		SUCCESS, // We got the lock!
		INUSE, // Already locked by someone else.
		UNSUPPORTED, // Locking probably not supported (e.g. NFS without lockd).
		FDLIMIT, // Process hit its file descriptor limit.
		UNKNOWN // The attempt failed for some unspecified reason.
	} reason;
	void *	lock_file( const std::string & filename, bool exclusive, FileSystem::reason & r, std::string & explanation ) {
		return get_internal().lock_file( filename, exclusive, r ,explanation );
	}
	void	unlock_file( const std::string & filename, void * pContext ) {
		return get_internal().unlock_file( filename, pContext );
	}
	bool	rename(const std::string & oldname, const std::string & newname) {
		return get_internal().rename( oldname, newname );
	}

	std::string get_description() {
		return get_internal().get_description();
	}

	File	create_changeset_file( const std::string & path, const std::string & name, std::string & changes_name );

	class Internal : public Xapian::Internal::RefCntBase
	{
	public:
		Internal() {}
		/// Virtual destructor.
		virtual ~Internal();
		virtual File	open(const std::string & path, int flags, int mod) = 0;
		virtual bool	make_dir( const std::string & path, int mod ) = 0;
		virtual bool	remove_dir(const std::string & path ) = 0;
		virtual bool	unlink( const std::string & file ) = 0;
		virtual void *	lock_file( const std::string & filename, bool exclusive, FileSystem::reason & r, std::string & explanation ) = 0;
		virtual void	unlock_file( const std::string & filename, void * pContext ) = 0;
		virtual bool	rename(const std::string & oldname, const std::string & newname) = 0;
		virtual bool	path_exist(const std::string & file, FileState * pState = NULL ) = 0;

		/// Return a string describing this object.
		virtual std::string get_description() const = 0;
	private:
		/// Copies are not allowed.
		Internal(const Internal &);
		/// Assignment is not allowed.
		void operator=(const Internal &);
	};
protected:
	Internal	&	get_internal();
	Xapian::Internal::RefCntPtr<Internal>	internal;
};

class XAPIAN_VISIBILITY_DEFAULT FileLock
{
public:
	typedef FileSystem::reason	reason;

	FileLock( const std::string & s, FileSystem system ) : filename(s),file_system( system ),context(NULL) {}
	~FileLock() { release(); }

	FileSystem::reason lock(bool exclusive, std::string & explanation);
	void				release();
	operator bool() const { return context != NULL; }

	void throw_databaselockerror(FileSystem::reason why,
		const std::string & db_dir,
		const std::string & explanation);

protected:
	std::string		filename;
	FileSystem		file_system;
	void	*		context;
};

}

#endif // XAPIAN_INCLUDED_FILESYSTEM_H
